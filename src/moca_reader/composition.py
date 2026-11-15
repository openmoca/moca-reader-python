"""Package spec §5.6 and Reader contract §9: binding by composition.

A composing package's own structure may use a member's package id (at any depth) or a member's node identifier as a
concept; the member's records are then bound to it, and to every concept that has it as a descendant, for the
concepts and scope filters, upTo and nodes().

Contract §3: the work stays roughly linear. A composition keeps only the direct bindings and the structure links above
them; a search walks down once from the concepts it needs, rather than listing every record's ancestors.
"""

from __future__ import annotations

import contextlib
from collections import deque
from typing import TYPE_CHECKING, Any
from weakref import WeakKeyDictionary

from ._js import js_sorted

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .reader import PackageResult

_cache: WeakKeyDictionary[Any, dict[str, Any] | None] = WeakKeyDictionary()


def composition_of(result: PackageResult) -> dict[str, Any] | None:
    """What a composing package's own structure binds its members to, or None when it has no valid members.

    One entry per resolved, valid, pin-matched member at any depth, each member once whatever the paths to it
    (contract §3), with ``id``, ``bound`` (the composer declares that id as a concept), ``nodes`` (the paths of its
    nodes whose identifiers are declared) and ``parents`` (the members that compose it within this composition).
    ``up`` holds, for each concept on the way up from those declared identifiers, its broader concepts and the
    concepts it is a part of, in the composer's own graph.
    """
    try:
        return _cache[result]
    except (KeyError, TypeError):
        pass
    graph = result.structure.graph if result.structure is not None else None

    def declared(iri: str) -> bool:
        c = graph.concepts.get(iri) if graph is not None else None
        return bool(c and c.declared)

    entries: dict[str, dict[str, Any]] = {}
    starts: list[str] = []
    queue: deque[tuple[list[Any], str | None]] = deque([(result.members, None)])
    visited = {result.digest}
    while queue:
        members, parent = queue.popleft()
        for m in members:
            child = m.result
            if m.status != "resolved" or child is None or not child.valid or not child.digest:
                continue
            if child.digest == result.digest:
                continue
            entry = entries.get(child.digest)
            if entry is None:
                mid = str(child.manifest.get("id"))
                nodes = js_sorted(n.path for n in child.nodes if declared(f"{mid}#{n.path}"))
                entry = {"digest": child.digest, "id": mid, "bound": declared(mid), "nodes": nodes, "parents": set()}
                entries[child.digest] = entry
                if entry["bound"]:
                    starts.append(mid)
                starts.extend(f"{mid}#{p}" for p in nodes)
            if parent is not None:
                entry["parents"].add(parent)
            if child.digest not in visited:
                visited.add(child.digest)
                queue.append((child.members, child.digest))
    # The links above each declared identifier, each concept walked once.
    up: dict[str, list[str]] = {}
    stack = list(starts)
    while stack:
        n = stack.pop()
        if n in up or graph is None:
            continue
        parents = js_sorted({e["iri"] for e in [*graph.out("broader", n), *graph.in_("hasPart", n)]})
        up[n] = parents
        stack.extend(p for p in parents if p not in up)
    out: dict[str, Any] | None = None
    if entries:
        out = {
            "members": [
                {
                    "digest": e["digest"],
                    "id": e["id"],
                    "bound": e["bound"],
                    "nodes": e["nodes"],
                    "parents": js_sorted(e["parents"]),
                }
                for e in (entries[d] for d in js_sorted(entries))
            ],
            "up": {k: up[k] for k in js_sorted(up) if up[k]},
        }
    with contextlib.suppress(TypeError):  # a result that cannot be weakly referenced is not cached
        _cache[result] = out
    return out


def _strings(value: Any) -> list[str]:
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


class Composer:
    """One composer's bindings, from composition_of or a package state, read defensively."""

    def __init__(self, digest: str, composition: dict[str, Any]) -> None:
        self.digest = digest
        self.members: dict[str, dict[str, Any]] = {}
        members = composition.get("members")
        for m in members if isinstance(members, list) else []:
            if not isinstance(m, dict) or not isinstance(m.get("digest"), str) or not isinstance(m.get("id"), str):
                continue
            self.members[m["digest"]] = {
                "digest": m["digest"],
                "id": m["id"],
                "bound": m.get("bound") is True,
                "nodes": set(_strings(m.get("nodes"))),
                "parents": _strings(m.get("parents")),
            }
        self.children: dict[str, list[str]] = {}
        up = composition.get("up")
        for n, parents in (up if isinstance(up, dict) else {}).items():
            for p in _strings(parents):
                self.children.setdefault(p, []).append(n)
        self.member_children: dict[str, list[str]] = {}
        for m in self.members.values():
            for p in m["parents"]:
                self.member_children.setdefault(p, []).append(m["digest"])
        self.has_bindings = any(m["bound"] or m["nodes"] for m in self.members.values())
        self._reach: dict[int, tuple[frozenset[str], set[str], set[str]]] = {}

    def _reached(self, wanted: frozenset[str]) -> tuple[set[str], set[str]]:
        """The concepts at or below ``wanted`` in this composer's links, and the members covered by them."""
        hit = self._reach.get(id(wanted))
        if hit is not None and hit[0] is wanted:
            return hit[1], hit[2]
        below = set(wanted)
        stack = list(wanted)
        while stack:
            for c in self.children.get(stack.pop(), []):
                if c not in below:
                    below.add(c)
                    stack.append(c)
        covered: set[str] = set()
        queue = [m["digest"] for m in self.members.values() if m["bound"] and m["id"] in below]
        while queue:
            d = queue.pop()
            if d in covered:
                continue
            covered.add(d)
            queue.extend(self.member_children.get(d, []))
        self._reach[id(wanted)] = (wanted, below, covered)
        return below, covered

    def binds(self, record: dict[str, Any], wanted: frozenset[str]) -> bool:
        """Whether this composer binds a record to a concept in ``wanted``, directly or as an ancestor of its binding."""
        digest = (record.get("package") or {}).get("digest")
        m = self.members.get(digest) if isinstance(digest, str) else None
        if m is None:
            return False
        below, covered = self._reached(wanted)
        if m["digest"] in covered:
            return True
        path = (record.get("node") or {}).get("path")
        return isinstance(path, str) and path in m["nodes"] and f"{m['id']}#{path}" in below


class CompositionIndex:
    """The loaded composing packages, by the digests of the members they hold."""

    def __init__(self, composers: Iterable[tuple[Any, Any]]) -> None:
        self.by_member: dict[str, list[Composer]] = {}
        self.has_bindings = False
        for digest, composition in composers:
            if not isinstance(digest, str) or not isinstance(composition, dict):
                continue
            composer = Composer(digest, composition)
            self.has_bindings = self.has_bindings or composer.has_bindings
            for d in composer.members:
                self.by_member.setdefault(d, []).append(composer)

    def composers_of(self, digest: Any) -> list[Composer]:
        return self.by_member.get(digest, []) if isinstance(digest, str) else []

    def bound_to(self, record: dict[str, Any], wanted: frozenset[str]) -> bool:
        """Whether a record is bound to a concept in ``wanted``: by its node's own concepts, or by composition."""
        if any(c in wanted for c in record.get("concepts") or []):
            return True
        return any(k.binds(record, wanted) for k in self.composers_of((record.get("package") or {}).get("digest")))
