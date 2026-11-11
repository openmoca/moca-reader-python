"""The Reader's search (Reader contract §9 and §10).

Pipeline: ingress hook -> backend -> resolve hits into citation records -> egress hook -> the gate. Backends and
hooks only propose candidates; the gate (digest allowlist, default retrieval policy, audience, locale, concepts and
scope) always runs last, so nothing either of them does can return content the policy excludes.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ._js import js_string, timestamp, truthy
from .audience import record_allowed
from .citation import CitationRecord, RelationIndex, citation_for, passes_default_policy, pick_representation
from .digest import utf8
from .state import refresh_record, state_index

if TYPE_CHECKING:
    from .library import Library
    from .reader import PackageResult
    from .structure_ops import StructureIndex

MAX_FETCH = 200
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


@dataclass
class _Context:
    now: datetime
    index: RelationIndex | None
    request: dict[str, Any]
    caller: MappingProxyType[str, Any]
    loaded: dict[str, PackageResult]
    hook_context: HookContext


class Search:
    """One entry point over a backend: ``search(query, limit=, include_all=, locale=, concepts=, scope=)``."""

    def __init__(
        self,
        source: Library | StoreScope,
        backend: SearchBackend,
        audiences: Sequence[str] | None = None,
        overfetch: int = 3,
        hooks: SearchHooks | None = None,
        allow_unlabelled: bool = False,
    ) -> None:
        from .library import Library

        if backend is None or not callable(getattr(backend, "search", None)):
            raise TypeError("Search needs a backend")
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
        self.backend = backend
        self.audiences = list(audiences) if audiences is not None else None
        # Contract §8 (moca-spec ADR-0016): unlabelled content is outside an audience set unless the host allows it.
        self.allow_unlabelled = allow_unlabelled is True
        self.overfetch = overfetch
        self.hooks = hooks or SearchHooks()

    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        include_all: bool = False,
        locale: str | None = None,
        concepts: Sequence[str] | None = None,
        scope: str | None = None,
    ) -> list[CitationRecord]:
        ctx = self._context(limit, include_all, locale, concepts, scope)
        if self.hooks.ingress is not None:
            _apply_ingress(ctx, self.hooks.ingress(query, ctx.hook_context))
        limit_, filters = self._plan(ctx)
        effective = ctx.request.get("query")
        hits = self.backend.search(effective if effective is not None else query, limit_, filters)
        candidates = self._resolve(hits, ctx)
        if self.hooks.egress is not None:
            candidates = self.hooks.egress(
                [{**r, "retrieval": {"via": "search"}} for r in candidates], ctx.hook_context
            )
        return self._gate(candidates, ctx)

    def _context(
        self, limit: int, include_all: bool, locale: str | None, concepts: Sequence[str] | None, scope: str | None
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
            }
        )
        request = dict(caller)
        loaded = {p.result.digest: p.result for p in self.library.packages} if self.library else {}
        hook_context = HookContext(
            MappingProxyType(request),
            self.library,
            self.library.structure if self.library else None,
            self.audiences,
            now,
        )
        return _Context(now, index, request, caller, loaded, hook_context)  # type: ignore[arg-type]

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
        if concepts:
            filters["concepts"] = concepts
        # Fetch more than the limit when the gate may drop hits (no pushdown), or when an egress hook reorders
        # them and needs candidates to choose from.
        pushdown = "filterPushdown" in (getattr(self.backend, "features", None) or [])
        fetch = (
            request["limit"]
            if pushdown and self.hooks.egress is None
            else min(request["limit"] * self.overfetch, MAX_FETCH)
        )
        return fetch, filters

    def _concepts(self, request: Any) -> list[str] | None:
        """The concepts a record must be bound to: the caller's, plus a scope and its descendants."""
        found = dict.fromkeys(request.get("concepts") or [])
        if request.get("scope"):
            found.setdefault(request["scope"])
            for c in self.library.structure.descendants(request["scope"]) if self.library else []:
                found.setdefault(c)
        return list(found) if found else None

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
        """The gate: always last, whatever the backend and the hooks did."""
        request = ctx.caller
        concepts = self._concepts(request)
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
            if concepts and not any(c in concepts for c in record.get("concepts") or []):
                continue
            span = record.get("span")
            # Contract §9.2: one result per node representation and span.
            locale = record["node"].get("locale") or ""
            key = f"{record['node'].get('ref')}\0{locale}\0{span.get('start', '') if isinstance(span, dict) else ''}"
            if key in seen:
                continue
            seen.add(key)
            out.append(record)
        if self.hooks.egress is None:
            out.sort(key=lambda r: -(r.get("score") or 0))
        return out[: request["limit"]]

    def _locale_ok(self, record: CitationRecord, locale: str, loaded: dict[str, PackageResult]) -> bool:
        result = loaded.get(record["package"].get("digest"))
        node = next((n for n in result.nodes if n.path == record["node"].get("path")), None) if result else None
        if node is None or result is None:
            want = locale.lower()
            have = (record["node"].get("locale") or "").lower()
            return have == want or want.startswith(f"{have}-") or have.startswith(f"{want}-")
        rep = pick_representation(node, locale)
        return bool((rep.locale or result.manifest.get("language")) == record["node"].get("locale"))


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
