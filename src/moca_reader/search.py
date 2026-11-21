"""The Reader's search (Reader contract §9 and §10).

Pipeline: ingress hook -> backend -> resolve hits into citation records -> egress hook -> the gate. Backends and
hooks only propose candidates; the gate (digest allowlist, default retrieval policy, audience, locale, concepts and
scope) always runs last, so nothing either of them does can return content the policy excludes.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ._js import js_sorted, js_string, timestamp, truthy
from .attestations import scope_covers
from .audience import record_allowed
from .citation import CitationRecord, RelationIndex, citation_for, passes_default_policy, pick_representation
from .composition import CompositionIndex, composition_of
from .diagnostics import Diagnostic, Diagnostics
from .digest import utf8
from .reading_order import ReadingOrder, passes_up_to
from .state import refresh_record, state_index
from .terms import UNSET, gate_reasons, rating_of, record_terms, resolve_ai, resolve_export

if TYPE_CHECKING:
    from .library import Library
    from .reader import PackageResult
    from .structure_ops import StructureIndex

SearchHit = dict[str, Any]  # search-hit.schema.json, plus "record" for store backends


@runtime_checkable
class SearchBackend(Protocol):
    """A search backend the host chooses (Reader contract §9.1). A package never chooses one."""

    @property
    def features(self) -> Sequence[str]:
        """ "lexical" or "dense", plus "filterPushdown"."""
        ...

    def search(self, query: str, limit: int, filters: dict[str, Any]) -> list[SearchHit]: ...


@runtime_checkable
class Embedder(Protocol):
    """A host-supplied embedder (Reader interface §5.3). A Reader never chooses one, and never adds text to what it embeds.

    ``query_prefix`` and ``document_prefix`` are declared for comparison with an index; the embedder applies its
    model's convention for each ``role`` ("query" or "document") itself.
    """

    name: str
    version: str | None
    dimensions: int
    query_prefix: str | None
    document_prefix: str | None

    def embed(self, texts: list[str], role: str) -> list[list[float]]: ...


@dataclass(frozen=True)
class HookContext:
    """Read-only context for retrieval hooks (Reader interface §5.4)."""

    request: MappingProxyType[str, Any]
    library: Library | None
    structure: StructureIndex | None
    audiences: list[str] | None
    now: datetime


Ingress = Callable[[str, HookContext], Any]
Egress = Callable[[list[CitationRecord], HookContext], list[CitationRecord]]


@dataclass(frozen=True)
class SearchHooks:
    """Retrieval hooks: host code, never package content (moca-spec ADR-0010)."""

    ingress: Ingress | None = None
    egress: Egress | None = None


@dataclass(frozen=True)
class StoreScope:
    """For a store backend: the states of the packages the host has loaded (``package_state``), and a clock.

    Contract §9.4: every library- and trust-dependent field of a stored record is recomputed from these states.
    """

    packages: Sequence[dict[str, Any]]
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    allow_unsigned_relations: bool = False
    # Contract §9.4: the structure source, a library of packages the host has read (a show and its seasons) whose
    # structure the hooks see and scope follows. It adds no records.
    structure: Library | None = None


@dataclass
class _Context:
    now: datetime
    index: RelationIndex | None
    request: dict[str, Any]
    caller: MappingProxyType[str, Any]
    loaded: dict[str, PackageResult]
    hook_context: HookContext
    # Package spec §5.6: what each loaded composing package binds its members to.
    composition: CompositionIndex
    findings: Diagnostics
    # Contract §15.4: the terms gate's removals by reason, in the latest round; None without a terms request.
    terms_excluded: dict[str, int] | None = None


class Search:
    """One entry point over a backend: ``search(query, limit=, include_all=, locale=, concepts=, scope=, up_to=)``."""

    def __init__(
        self,
        source: Library | StoreScope,
        backend: SearchBackend,
        audiences: Sequence[str] | None = None,
        overfetch: int = 3,
        hooks: SearchHooks | None = None,
        allow_unlabelled: bool = False,
        max_candidates: int | None = None,
        terms_limits: dict[str, Any] | None = None,
    ) -> None:
        from .library import Library

        if backend is None or not callable(getattr(backend, "search", None)):
            raise TypeError("Search needs a backend")
        if max_candidates is not None and (
            isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or max_candidates < 1
        ):
            raise ValueError("max_candidates must be an integer of at least 1")
        self.library: Library | None = source if isinstance(source, Library) else None
        self.states: dict[str, dict[str, Any]] | None = (
            None if isinstance(source, Library) else {s["digest"]: s for s in source.packages}
        )
        self.allowed: set[str] | None = None if self.states is None else set(self.states)
        self.store_index = (
            None
            if self.states is None or isinstance(source, Library)
            else state_index(self.states, source.allow_unsigned_relations)
        )
        self.clock: Callable[[], datetime] = source.clock
        # Contract §9.4: the structure the hooks and scope see; a store search's comes from its structure source.
        self.structure: StructureIndex | None = (
            source.structure
            if isinstance(source, Library)
            else (source.structure.structure if source.structure else None)
        )
        # Contract §9, Members: with the host's opt-in for its own packages, unsigned composers limit their members too.
        self.allow_unsigned = (
            source.allow_unsigned_relations is True if isinstance(source, (Library, StoreScope)) else False
        )
        self.backend = backend
        self.audiences = list(audiences) if audiences is not None else None
        # Contract §8 (moca-spec ADR-0016): unlabelled content is outside an audience set unless the host allows it.
        self.allow_unlabelled = allow_unlabelled is True
        self.overfetch = overfetch
        # Contract §9.2: the host's bound on the candidates one search call examines; None for no bound.
        self.max_candidates = max_candidates
        self.hooks = hooks or SearchHooks()
        # Contract §15.3 step 4: the host's own `ai` values, floors that only tighten.
        self.terms_limits: Any = terms_limits if isinstance(terms_limits, (dict, list)) else UNSET
        # The findings of the latest search() call, such as S008 (Reader interface §5.1).
        self.diagnostics: list[Diagnostic] = []

    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        include_all: bool = False,
        locale: str | None = None,
        concepts: Sequence[str] | None = None,
        scope: str | None = None,
        up_to: str | None = None,
        terms: dict[str, Any] | None = None,
    ) -> list[CitationRecord]:
        """``terms`` is the host's terms request (contract §15.4): ``{"ai": {"destination", "conditions", "use"},
        "rating": {...}}``. Without it, terms remove nothing."""
        ctx = self._context(limit, include_all, locale, concepts, scope, up_to, terms)
        if self.hooks.ingress is not None:
            _apply_ingress(ctx, self.hooks.ingress(query, ctx.hook_context))
        size, filters = self._plan(ctx)
        effective = ctx.request.get("query")
        # Contract §9.2, "Filters come before the limit": ask again, for more each time, until limit records pass
        # the gate or the backend has no more.
        while True:
            hits = self.backend.search(effective if effective is not None else query, size, filters)
            candidates = self._narrow(self._resolve(hits, ctx), ctx)
            if self.hooks.egress is not None:
                candidates = self.hooks.egress(
                    [{**r, "retrieval": {"via": "search"}} for r in candidates], ctx.hook_context
                )
            passed = self._gate(candidates, ctx)
            want = ctx.caller["limit"]
            if len(passed) >= want or not isinstance(hits, list) or len(hits) < size:
                return self._finish(passed, ctx)
            if self.max_candidates is not None and size >= self.max_candidates:
                ctx.findings.add(
                    "S010_SEARCH_TRUNCATED",
                    f"stopped at maxCandidates {self.max_candidates} with {len(passed)} of {want} records",
                )
                self.diagnostics = ctx.findings.items
                return self._finish(passed, ctx)
            size = size * 2 if self.max_candidates is None else min(size * 2, self.max_candidates)

    def _finish(self, passed: list[CitationRecord], ctx: _Context) -> list[CitationRecord]:
        """The records the caller keeps, and the terms gate's count by reason (U004, contract §15.4)."""
        kept = passed[: ctx.caller["limit"]]
        if ctx.terms_excluded:
            counts = ", ".join(f"{k}: {n}" for k, n in js_sorted(ctx.terms_excluded.items(), key=lambda kv: kv[0]))
            ctx.findings.add("U004_TERMS_EXCLUDED", f"the terms request removed records ({counts})")
            self.diagnostics = ctx.findings.items
        return kept

    def _context(
        self,
        limit: int,
        include_all: bool,
        locale: str | None,
        concepts: Sequence[str] | None,
        scope: str | None,
        up_to: str | None,
        terms: Any = None,
    ) -> _Context:
        now = self.clock()
        index = self.library.relation_index() if self.library else None
        # The caller's request binds the gate. Ingress may change the query and what the backend searches
        # (contract §9.2), never the limit, the opt-in, the locale or what the gate keeps.
        caller = MappingProxyType(
            {
                "limit": limit,
                "includeAll": include_all,
                "locale": locale,
                "concepts": tuple(concepts) if concepts else None,
                "scope": scope,
                "upTo": up_to,
                # Contract §15.4: the terms request is the caller's; a hook can never widen it.
                "terms": copy.deepcopy(terms) if isinstance(terms, (dict, list)) else None,
            }
        )
        request = dict(caller)
        loaded = {p.result.digest: p.result for p in self.library.packages} if self.library else {}
        findings = Diagnostics()
        # Contract §9: an upTo that no loaded reading order places limits nothing, and never silently.
        if isinstance(up_to, str):
            digests = list(loaded) if self.library else list(self.states or {})
            if not any(
                (order := self._reading_order(d, loaded)) is not None and up_to in order.positions for d in digests
            ):
                findings.add(
                    "S008_UPTO_UNRESOLVED", f"upTo {up_to} is on no loaded package's reading order; it limits nothing"
                )
        self.diagnostics = findings.items
        hook_context = HookContext(
            MappingProxyType(request),
            self.library,
            self.structure,
            self.audiences,
            now,
        )
        composition = CompositionIndex(
            [(r.digest, composition_of(r)) for r in loaded.values()]
            if self.library
            else [(s.get("digest"), s.get("composition")) for s in (self.states or {}).values() if isinstance(s, dict)]
        )
        return _Context(now, index, request, caller, loaded, hook_context, composition, findings)  # type: ignore[arg-type]

    def _plan(self, ctx: _Context) -> tuple[int, dict[str, Any]]:
        request = ctx.request
        exclude: list[dict[str, str]] = []
        if not request["includeAll"] and self.library:
            for p in self.library.packages:
                for node in p.result.nodes:
                    if all(
                        not passes_default_policy(citation_for(p.result, node, rep, ctx.now, ctx.index))
                        for rep in node.representations
                    ):
                        exclude.append(
                            {
                                "digest": p.result.digest or "",
                                "node": f"{js_string(p.result.manifest.get('id'))}#{node.path}",
                            }
                        )
        concepts = self._concepts(request)
        filters: dict[str, Any] = {
            "digests": [p.result.digest for p in self.library.packages] if self.library else list(self.allowed or []),
            "exclude": exclude,
        }
        if self.audiences is not None:
            filters["audiences"] = self.audiences
            filters["allowUnlabelled"] = self.allow_unlabelled
        if request.get("locale"):
            filters["locale"] = request["locale"]
        # Contract §9.5: a record bound by composition carries none of those concepts itself, so the filter is left
        # to the gate when any loaded package binds members.
        if concepts and not ctx.composition.has_bindings:
            filters["concepts"] = concepts
        # The search's own candidate check for what has no pushdown filter: upTo, and concepts bound by composition.
        # Backends that know it (the Reader's own) apply it after scoring; the gate still checks every candidate.
        accept = self._accept(ctx, concepts)
        if accept is not None:
            filters["accept"] = accept
        # Ask for more than the limit when the gate may drop hits (no pushdown, or a filter with no pushdown), or
        # when an egress hook reorders them and needs candidates to choose from. Either way the search asks again
        # while too few pass (contract §9.2).
        pushdown = "filterPushdown" in (getattr(self.backend, "features", None) or [])
        first = (
            request["limit"]
            if pushdown
            and self.hooks.egress is None
            and not isinstance(request.get("upTo"), str)
            and request.get("terms") is None
            and not (concepts and ctx.composition.has_bindings)
            else request["limit"] * self.overfetch
        )
        if self.max_candidates is not None:
            first = min(first, self.max_candidates)
        return max(1, first), filters

    def _accept(self, ctx: _Context, concepts: list[str] | None) -> Callable[[dict[str, Any]], bool] | None:
        """The candidate check for upTo and for concepts bound by composition, on a hit before it is resolved: the
        gate's own tests (steps 5.5 and 5.6) on the node's package, path and concepts. Library searches only."""
        if not self.library:
            return None
        up_to = ctx.caller.get("upTo")
        up_to = up_to if isinstance(up_to, str) else None
        composed = frozenset(concepts) if concepts and ctx.composition.has_bindings else None
        if up_to is None and composed is None:
            return None
        late: dict[str, tuple[ReadingOrder, frozenset[str]] | None] = {}
        paths: dict[str, dict[str, Any]] = {}

        def accept(hit: dict[str, Any]) -> bool:
            result = ctx.loaded.get(str(hit.get("digest")))
            if result is None:
                return True
            by_path = paths.get(result.digest or "")
            if by_path is None:
                by_path = paths[result.digest or ""] = {n.path: n for n in result.nodes}
            node = by_path.get(str(hit.get("path")))
            rep = (
                next((r for r in node.representations if (r.locale or None) == (hit.get("locale") or None)), None)
                if node is not None
                else None
            )
            if rep is None:
                return True
            record: dict[str, Any] = {
                "package": {"digest": result.digest, "id": js_string(result.manifest.get("id"))},
                "node": {"path": hit.get("path")},
                "concepts": list(rep.concepts or []),
            }
            if composed is not None and not ctx.composition.bound_to(record, composed):
                return False
            return up_to is None or self._passes_up_to(record, up_to, ctx, late)

        return accept

    def _concepts(self, request: Any) -> list[str] | None:
        """The concepts a record must be bound to: the caller's, plus a scope and its descendants."""
        found = dict.fromkeys(request.get("concepts") or [])
        if request.get("scope"):
            found.setdefault(request["scope"])
            for c in self.structure.descendants(request["scope"]) if self.structure else []:
                found.setdefault(c)
        return list(found) if found else None

    def _narrow(self, candidates: list[CitationRecord], ctx: _Context) -> list[CitationRecord]:
        """Contract §9.2, "Ingress narrowing": concepts or a scope an ingress hook set keep only records bound to them,
        by their own concepts or by composition, after the backend and before the egress hook and the gate, on every
        round."""
        request, caller = ctx.request, ctx.caller
        if request.get("concepts") == caller["concepts"] and request.get("scope") == caller["scope"]:
            return candidates
        concepts = self._concepts(request)
        if not concepts:
            return candidates
        wanted = frozenset(concepts)
        return [r for r in candidates if ctx.composition.bound_to(r, wanted)]

    def _resolve(self, hits: Any, ctx: _Context) -> list[CitationRecord]:
        """Backend hits as citation records; hits that do not resolve are dropped."""
        out: list[CitationRecord] = []
        for hit in hits if isinstance(hits, list) else []:
            if isinstance(hit, dict) and truthy(hit.get("record")):
                refreshed = (
                    _refresh_clock(hit["record"], ctx.now)
                    if self.library
                    else refresh_record(hit["record"], ctx.now, self.states or {}, self.store_index or ({}, {}))
                )
                if refreshed is not None:
                    out.append({**refreshed, "score": hit.get("score")})
                continue
            result = ctx.loaded.get(str(hit.get("digest"))) if isinstance(hit, dict) else None
            if result is None or hit.get("node") != f"{js_string(result.manifest.get('id'))}#{hit.get('path')}":
                continue
            node = next((n for n in result.nodes if n.path == hit.get("path")), None)
            rep = (
                next((r for r in node.representations if (r.locale or None) == (hit.get("locale") or None)), None)
                if node
                else None
            )
            if node is None or rep is None:
                continue
            span = hit.get("span")
            text = _slice_body(rep, span) if span else rep.body
            if text is None:
                continue
            record = citation_for(result, node, rep, ctx.now, ctx.index, text)
            if span:
                record["span"] = {"start": span["start"], "end": span["end"]}
            out.append({**record, "score": hit.get("score")})
        return out

    def _gate(self, candidates: Any, ctx: _Context) -> list[CitationRecord]:
        """The gate: always last, whatever the backend and the hooks did. Every record that passes, best first; the
        caller keeps the limit."""
        request = ctx.caller
        # Counted afresh each round: the last round's count is the one reported.
        ctx.terms_excluded = {} if request.get("terms") is not None else None
        concepts = self._concepts(request)
        wanted = frozenset(concepts) if concepts else None
        late: dict[str, tuple[ReadingOrder, frozenset[str]] | None] = {}
        allowed = set(ctx.loaded) if self.library else (self.allowed or set())
        seen: set[str] = set()
        out: list[CitationRecord] = []
        for record in candidates if isinstance(candidates, list) else []:
            if not isinstance(record, dict) or not all(truthy(record.get(k)) for k in ("package", "node", "trust")):
                continue
            if record["package"].get("digest") not in allowed:
                continue
            if not request["includeAll"] and not passes_default_policy(record):
                continue
            if not record_allowed(record, self.audiences, self.allow_unlabelled):
                continue
            if request["locale"] and not self._locale_ok(record, request["locale"], ctx.loaded):
                continue
            if wanted is not None and not ctx.composition.bound_to(record, wanted):
                continue
            # Contract §9.2 step 6: upTo follows the caller; an ingress hook never changes it.
            up_to = request.get("upTo")
            if isinstance(up_to, str) and not self._passes_up_to(record, up_to, ctx, late):
                continue
            span = record.get("span")
            # Contract §9.2: one result per node representation and span, the whole span: start and end.
            locale = record["node"].get("locale") or ""
            start, end = (span.get("start", ""), span.get("end", "")) if isinstance(span, dict) else ("", "")
            key = f"{record['node'].get('ref')}\0{locale}\0{_key_part(start)}\0{_key_part(end)}"
            if key in seen:
                continue
            # Contract §9.2 step 5.3 and §15.4: with a terms request, the terms gate.
            kept = record
            if ctx.terms_excluded is not None:
                termed = self._terms(record, request["terms"], ctx)
                if termed is None:
                    continue
                kept = termed
            seen.add(key)
            out.append(kept)
        if self.hooks.egress is None:
            out.sort(key=lambda r: -(r.get("score") or 0))
        return out

    def _terms(self, record: CitationRecord, request: Any, ctx: _Context) -> CitationRecord | None:
        """Contract §15.3-15.4: the record with its resolved terms, or None when the terms gate removes it (counted
        by reason). A package with no terms result (its manifest failed its schema) has every field at its
        strictest."""

        from .reader import terms_source_of

        def source_of(digest: Any) -> Any:
            if self.library:
                return terms_source_of(ctx.loaded.get(digest))
            state = (self.states or {}).get(digest)
            return state.get("terms") if isinstance(state, dict) else None

        package = record["package"]
        source = source_of(package.get("digest"))
        # Contract §15.3 step 3: a composing package's terms apply only when its signers speak for the member, as for
        # upTo (§9), or the host allows unsigned packages to. A composer with no terms result counts as setting
        # nothing.
        composites: list[Any] = []
        for composer in ctx.composition.composers_of(package.get("digest")):
            if not self.allow_unsigned and not scope_covers(
                self._relation_scopes(composer.digest, ctx.loaded), package.get("id")
            ):
                continue
            c = source_of(composer.digest)
            if isinstance(c, dict) and truthy(c.get("terms")):
                composites.append(c["terms"])
        pkg = source if isinstance(source, dict) else _STRICTEST_SOURCE
        path = record["node"].get("path")
        path = path if isinstance(path, str) else ""
        ai = resolve_ai(pkg, path, self.terms_limits, composites)
        rating = rating_of(pkg.get("terms"), path)
        reasons = gate_reasons(request if isinstance(request, dict) else {}, ai, rating)
        if reasons:
            assert ctx.terms_excluded is not None
            for r in reasons:
                ctx.terms_excluded[r] = ctx.terms_excluded.get(r, 0) + 1
            return None
        return {**record, "terms": record_terms(pkg.get("authority"), ai, rating, resolve_export(pkg, composites))}

    def _passes_up_to(
        self,
        record: dict[str, Any],
        up_to: str,
        ctx: _Context,
        late: dict[str, tuple[ReadingOrder, frozenset[str]] | None],
    ) -> bool:
        """Contract §9: the record's own package limits it by the node's own concepts; each loaded package that
        holds it as a member and whose reading order places upTo limits it by the node's own concepts and the
        concepts it binds it to: none of them, or their ancestors, may come after upTo."""
        if not passes_up_to(record, self._reading_order(record["package"].get("digest"), ctx.loaded), up_to):
            return False
        for composer in ctx.composition.composers_of(record["package"].get("digest")):
            # Contract §9, Members: a composer limits a member only when its signers speak for the member (as for
            # relations, R004), or the host allows unsigned packages to.
            if not self.allow_unsigned and not scope_covers(
                self._relation_scopes(composer.digest, ctx.loaded), record["package"].get("id")
            ):
                continue
            if composer.digest not in late:
                order = self._reading_order(composer.digest, ctx.loaded)
                late[composer.digest] = (
                    (order, _late_concepts(order, up_to)) if order is not None and up_to in order.positions else None
                )
            entry = late[composer.digest]
            if entry is None:
                continue
            if not passes_up_to(record, entry[0], up_to) or composer.binds(record, entry[1]):
                return False
        return True

    def _relation_scopes(self, digest: str, loaded: dict[Any, PackageResult]) -> list[str]:
        if self.library:
            result = loaded.get(digest)
            scopes: Any = result.relation_scopes if result is not None else []
        else:
            scopes = ((self.states or {}).get(digest) or {}).get("relationScopes")
        return [s for s in scopes if isinstance(s, str)] if isinstance(scopes, list) else []

    def _reading_order(self, digest: Any, loaded: dict[Any, PackageResult]) -> ReadingOrder | None:
        if self.library:
            result = loaded.get(digest)
            return result._reading_order if result is not None else None
        state = (self.states or {}).get(digest)
        return ReadingOrder.from_state(state.get("readingOrder")) if state else None

    def _locale_ok(self, record: CitationRecord, locale: str, loaded: dict[str, PackageResult]) -> bool:
        result = loaded.get(record["package"].get("digest"))
        node = next((n for n in result.nodes if n.path == record["node"].get("path")), None) if result else None
        if node is None or result is None:
            want = locale.lower()
            have = (record["node"].get("locale") or "").lower()
            return have == want or want.startswith(f"{have}-") or have.startswith(f"{want}-")
        rep = pick_representation(node, locale)
        return bool((rep.locale or result.manifest.get("language")) == record["node"].get("locale"))


# A package with no terms result: every field at its strictest (contract §15.3).
_STRICTEST_SOURCE: dict[str, Any] = {
    "terms": {
        "ai": {
            "allowed": {
                "device": False,
                "host": False,
                "provider": False,
                "training": False,
                "machineTranslation": False,
            },
            "answerSources": "work",
        },
        "rights": {"export": {"allowed": False}},
    },
    "authority": "unverified",
}


def _key_part(value: Any) -> str:
    """A span offset as JavaScript writes it into a string key."""
    return value if isinstance(value, str) else js_string(value)


def _late_concepts(order: ReadingOrder, up_to: str) -> frozenset[str]:
    """The concepts a reading order places after upTo (contract §9)."""
    limit = order.positions[up_to]
    return frozenset(c for c, n in order.positions.items() if n > limit)


def _apply_ingress(ctx: _Context, result: Any) -> None:
    """What an ingress hook may change: the query, and the concepts or scope the backend searches."""
    if not isinstance(result, dict):
        return
    if isinstance(result.get("query"), str):
        ctx.request["query"] = result["query"]
    if isinstance(result.get("concepts"), list):
        ctx.request["concepts"] = list(result["concepts"])
    if isinstance(result.get("scope"), str):
        ctx.request["scope"] = result["scope"]


def _refresh_clock(record: CitationRecord, now: datetime) -> CitationRecord:
    """A stored citation record with its clock-dependent fields recomputed for now."""
    t = now.timestamp() * 1000
    trust = dict(record["trust"])
    trust["stale"] = t >= timestamp(trust["staleAfter"]) if truthy(trust.get("staleAfter")) else False
    trust["inForce"] = (not truthy(trust.get("validFrom")) or t >= timestamp(trust["validFrom"])) and (
        not truthy(trust.get("validUntil")) or t < timestamp(trust["validUntil"])
    )
    return {**record, "trust": trust}


def _slice_body(rep: Any, span: dict[str, Any]) -> str | None:
    """The text of a byte span inside a representation's body, or None."""
    body = utf8(rep.body)
    start: Any = span.get("start")
    end: Any = span.get("end")
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and float(v).is_integer() for v in (start, end)):
        return None
    lo, hi = int(start) - rep.body_offset, int(end) - rep.body_offset
    if lo < 0 or hi < lo or hi > len(body):
        return None
    return body[lo:hi].decode("utf-8", errors="replace")
