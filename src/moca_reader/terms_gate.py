"""The terms gate's shared view of a set of packages (Reader contract §15.3-15.4, moca-spec ADR-0041).

Each node's resolved terms, and whether a package is closed or hidden for a request. Search, ingest, the structure
operations and the catalogue all use it, so they agree on what is closed.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from ._js import js_sorted, truthy
from .attestations import scope_covers
from .composition import CompositionIndex, composition_of
from .diagnostics import Diagnostic, Diagnostics
from .terms import UNSET, Resolved, closure_of, rating_of, resolve_ai

if TYPE_CHECKING:
    from .library import Library

STRICTEST_SOURCE: Final[dict[str, Any]] = {
    "terms": {
        "ai": {
            "allowed": {
                "device": False,
                "host": False,
                "provider": False,
                "training": False,
                "machineTranslation": False,
                "mention": False,
            },
            "answerSources": "work",
        },
        "rights": {"export": {"allowed": False}},
    },
    "authority": "unverified",
}
"""What a package with no terms result counts as: every permission at its strictest (contract §15.3)."""

_OPEN: Final[dict[str, Any]] = {"closed": False, "closedBy": [], "hidden": False}


@dataclass(frozen=True)
class GatePackage:
    """One package as the gate sees it: from a loaded result or a package state (contract §9.4)."""

    digest: str
    id: Any
    version: Any
    source: dict[str, Any] | None
    relation_scopes: list[str] = field(default_factory=list)


@dataclass
class NodeTerms:
    pkg: Mapping[str, Any]
    composites: list[Any]
    ai: dict[str, Resolved]
    rating: Any


class TermsResolver:
    """Resolves terms over a set of packages for one request.

    ``composition`` says which loaded packages compose which; ``allow_unsigned`` lets unsigned composing packages
    speak for their members; ``terms_limits`` are the host's own ``ai`` values (floors, never values); ``request``
    the terms request, for closed and hidden.
    """

    def __init__(
        self,
        packages: Iterable[GatePackage],
        composition: CompositionIndex | None = None,
        allow_unsigned: bool = False,
        terms_limits: Any = UNSET,
        request: Any = None,
    ) -> None:
        self.by_digest = {p.digest: p for p in packages}
        self.composition = composition
        self.allow_unsigned = allow_unsigned
        self.terms_limits = terms_limits if isinstance(terms_limits, (dict, list)) else UNSET
        self.request = request
        self._closures: dict[str, dict[str, Any]] = {}
        self._hidden_names: list[str] | None = None

    def source(self, digest: Any) -> Mapping[str, Any]:
        """The package's terms source, or the strictest when it has none."""
        p = self.by_digest.get(digest)
        return p.source if p is not None and isinstance(p.source, dict) else STRICTEST_SOURCE

    def composites(self, digest: Any) -> list[Any]:
        """Contract §15.3 step 3: the terms of the composing packages whose signers speak for this package, as for
        upTo (§9), or of every composing package when the host allows unsigned ones. A composer with no terms result
        counts as setting nothing."""
        own = self.by_digest.get(digest)
        package_id = own.id if own is not None else None
        out: list[Any] = []
        for composer in self.composition.composers_of(digest) if self.composition else []:
            p = self.by_digest.get(composer.digest)
            if not self.allow_unsigned and not scope_covers(p.relation_scopes if p else [], package_id):
                continue
            c = p.source if p is not None else None
            if isinstance(c, dict) and truthy(c.get("terms")):
                out.append(c["terms"])
        return out

    def node_terms(self, digest: Any, path: str) -> NodeTerms:
        """A node's resolved ``ai`` terms and effective rating, with the package source and composites they came
        from."""
        pkg = self.source(digest)
        composites = self.composites(digest)
        ai = resolve_ai(pkg, path, self.terms_limits, composites)
        return NodeTerms(pkg, composites, ai, rating_of(pkg.get("terms"), path))

    def _asks_ai(self) -> bool:
        return isinstance(self.request, dict) and isinstance(self.request.get("ai"), (dict, list))

    def closure(self, digest: Any) -> dict[str, Any]:
        """Contract §15.4: whether the package is closed, and hidden, for the request."""
        if not self._asks_ai():
            return _OPEN
        found = self._closures.get(digest)
        if found is None:
            ai = resolve_ai(self.source(digest), None, self.terms_limits, self.composites(digest))
            found = closure_of(self.request, ai)
            self._closures[digest] = found
        return found

    def names_hidden(self, ref: Any) -> bool:
        """Contract §15.4, "Nothing names a hidden package": whether a reference (a package id, an id@version, or a
        node id under either, as in trust.supersededBy and trust.contestedBy) names a package hidden for the
        request."""
        if not isinstance(ref, str) or not self._asks_ai():
            return False
        if self._hidden_names is None:
            self._hidden_names = []
            for digest, p in self.by_digest.items():
                if self.closure(digest)["hidden"] and isinstance(p.id, str):
                    self._hidden_names += [p.id, f"{p.id}@{p.version}"]
        return any(ref == n or ref.startswith(f"{n}#") for n in self._hidden_names)

    def without_hidden(self, record: dict[str, Any]) -> dict[str, Any]:
        """A record whose ``trust.supersededBy`` and ``trust.contestedBy`` leave out every entry that names a hidden
        package; ``superseded`` and ``contested`` keep their values."""
        trust = record.get("trust")
        if not isinstance(trust, dict) or not (trust.get("supersededBy") or trust.get("contestedBy")):
            return record
        nxt = dict(trust)
        for key in ("supersededBy", "contestedBy"):
            refs = trust.get(key)
            if not isinstance(refs, list):
                continue
            kept = [r for r in refs if not self.names_hidden(r)]
            if kept:
                nxt[key] = kept
            else:
                nxt.pop(key, None)
        return {**record, "trust": nxt}


def library_resolver(library: Library, terms_limits: Any = UNSET, request: Any = None) -> TermsResolver:
    """A resolver over a library's loaded packages."""
    from .reader import terms_source_of

    return TermsResolver(
        [
            GatePackage(
                p.result.digest or "",
                p.result.manifest.get("id"),
                p.result.manifest.get("version"),
                terms_source_of(p.result),
                [s for s in p.result.relation_scopes if isinstance(s, str)],
            )
            for p in library.packages
        ],
        CompositionIndex([(p.result.digest, composition_of(p.result)) for p in library.packages]),
        library.allow_unsigned_relations is True,
        terms_limits,
        request,
    )


def state_resolver(
    states: Mapping[str, Mapping[str, Any]],
    composition: CompositionIndex | None,
    allow_unsigned: bool,
    terms_limits: Any = UNSET,
    request: Any = None,
) -> TermsResolver:
    """A resolver over package states (contract §9.4), for a store search."""
    packages = []
    for digest, s in states.items():
        scopes = s.get("relationScopes")
        terms = s.get("terms")
        packages.append(
            GatePackage(
                digest,
                s.get("id"),
                s.get("version"),
                terms if isinstance(terms, dict) else None,
                [x for x in scopes if isinstance(x, str)] if isinstance(scopes, list) else [],
            )
        )
    return TermsResolver(packages, composition, allow_unsigned, terms_limits, request)


class TermsCount:
    """The U004 finding's counts (contract §15.4): removed units by reason, and how many came from hidden
    packages."""

    def __init__(self) -> None:
        self.reasons: dict[str, int] = {}
        self.hidden = 0

    def add(self, reasons: Iterable[str], hidden: bool) -> None:
        for r in reasons:
            self.reasons[r] = self.reasons.get(r, 0) + 1
        if hidden:
            self.hidden += 1

    def __bool__(self) -> bool:
        return bool(self.reasons)

    def report(self, diagnostics: Diagnostics, what: str) -> Diagnostic | None:
        """Adds U004 to ``diagnostics``, with ``excluded`` and ``hidden``, when anything was removed."""
        if not self.reasons:
            return None
        ordered = js_sorted(self.reasons.items(), key=lambda kv: kv[0])
        counts = ", ".join(f"{k}: {n}" for k, n in ordered)
        entry = diagnostics.add(
            "U004_TERMS_EXCLUDED", f"the terms request removed {what} ({counts}; from hidden packages: {self.hidden})"
        )
        entry.excluded = dict(ordered)
        entry.hidden = self.hidden
        return entry
