"""Package spec §5.6 and Reader contract §9: binding by composition.

A composing package's own structure may use a member's package id (at any depth) or a member's node identifier as a
concept; the member's records are then bound to it, and to every concept that has it as a descendant, for the
concepts and scope filters and for upTo.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any
from weakref import WeakKeyDictionary

from ._js import js_sorted

if TYPE_CHECKING:
    from .reader import Member, PackageResult
    from .structure import StructureGraph


def _with_ancestors(graph: StructureGraph, iri: str) -> set[str]:
    """The concept and every concept that has it as a descendant, by broader or hasPart, in one graph."""
    out = {iri}
    stack = [iri]
    while stack:
        n = stack.pop()
        for e in [*graph.out("broader", n), *graph.in_("hasPart", n)]:
            if e["iri"] not in out:
                out.add(e["iri"])
                stack.append(e["iri"])
    return out


_bindings: WeakKeyDictionary[Any, list[dict[str, Any]]] = WeakKeyDictionary()


def composition_of(result: PackageResult) -> list[dict[str, Any]]:
    """What a composing package's own structure binds its resolved members to: one entry per member digest, with the
    concepts every record of that member is bound to, and the concepts each node path is bound to. Only members that
    resolved and matched their pin, and are valid, are bound."""
    try:
        return _bindings[result]
    except (KeyError, TypeError):
        pass
    graph = result.structure.graph if result.structure is not None else None

    def declared(iri: str) -> bool:
        c = graph.concepts.get(iri) if graph is not None else None
        return bool(c and c.declared)

    by_digest: dict[str, tuple[set[str], dict[str, set[str]]]] = {}

    def visit(members: list[Member], chain: list[str], seen: set[str]) -> None:
        for m in members:
            child = m.result
            if m.status != "resolved" or child is None or not child.valid or not child.digest or child.digest in seen:
                continue
            ids = [*chain, str(child.manifest.get("id"))]
            if graph is not None:
                concepts, nodes = by_digest.setdefault(child.digest, (set(), {}))
                for i in ids:
                    if declared(i):
                        concepts.update(_with_ancestors(graph, i))
                for node in child.nodes:
                    node_id = f"{ids[-1]}#{node.path}"
                    if declared(node_id):
                        nodes.setdefault(node.path, set()).update(_with_ancestors(graph, node_id))
            visit(child.members, ids, {*seen, child.digest})

    visit(result.members, [], {result.digest} if result.digest else set())
    out = [
        {
            "digest": digest,
            "concepts": js_sorted(concepts),
            "nodes": {p: js_sorted(s) for p, s in js_sorted(nodes.items(), key=lambda kv: kv[0])},
        }
        for digest, (concepts, nodes) in js_sorted(by_digest.items(), key=lambda kv: kv[0])
        if concepts or nodes
    ]
    with contextlib.suppress(TypeError):
        _bindings[result] = out
    return out


def composition_index(composers: list[tuple[Any, Any]]) -> dict[str, list[dict[str, Any]]]:
    """An index from member digest to the bindings each loaded composing package gives it.

    ``composers`` holds (composer digest, its composition), from results or from package states.
    """
    index: dict[str, list[dict[str, Any]]] = {}
    for digest, composition in composers:
        if not isinstance(composition, list):
            continue
        for e in composition:
            if (
                not isinstance(e, dict)
                or not isinstance(e.get("digest"), str)
                or not isinstance(e.get("concepts"), list)
            ):
                continue
            nodes = e.get("nodes") if isinstance(e.get("nodes"), dict) else {}
            index.setdefault(e["digest"], []).append(
                {"composer": digest, "concepts": [c for c in e["concepts"] if isinstance(c, str)], "nodes": nodes}
            )
    return index


def composed_concepts(entry: dict[str, Any], record: dict[str, Any]) -> list[str]:
    """The concepts one composing package binds a record to."""
    path = (record.get("node") or {}).get("path")
    own = entry["nodes"].get(path) if isinstance(path, str) else None
    return [*entry["concepts"], *(c for c in (own if isinstance(own, list) else []) if isinstance(c, str))]


def bound_concepts(record: dict[str, Any], index: dict[str, list[dict[str, Any]]]) -> list[str]:
    """A record's concepts for the concepts and scope filters: its node's own, and every binding by composition."""
    out = dict.fromkeys(record.get("concepts") or [])
    digest = (record.get("package") or {}).get("digest")
    for e in index.get(digest, []) if isinstance(digest, str) else []:
        out.update(dict.fromkeys(composed_concepts(e, record)))
    return list(out)
