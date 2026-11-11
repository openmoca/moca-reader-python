"""Structure operations (Reader contract §10): lookups over the merged structure of every loaded package plus the
host's overlays. They are facts, so every Reader answers them identically; each result says which layer stated it."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._js import js_sorted, utf16_key
from .citation import CitationRecord, passes_default_policy
from .structure import Fact, StructureGraph, preferred

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .library import Library


class StructureIndex:
    def __init__(self, library: Library, overlay_facts: list[Fact] | None = None) -> None:
        self.library = library
        facts = [f for p in library.packages if p.result.structure is not None for f in p.result.structure.facts]
        self.graph = StructureGraph([*facts, *(overlay_facts or [])])

    def _item(self, iri: str, at: dict[str, Any]) -> dict[str, Any]:
        c = self.graph.concepts.get(iri)
        label = preferred(c.labels) if c else None
        item: dict[str, Any] = {"iri": iri}
        if label is not None:
            item["label"] = label
        item["layer"] = at["layer"]
        return item

    def concept(self, iri: str) -> dict[str, Any] | None:
        """A concept, or None when no layer declares it."""
        c = self.graph.concepts.get(iri)
        if c is None or not c.declared:
            return None
        label, definition = preferred(c.labels), preferred(c.definitions)
        out: dict[str, Any] = {"iri": iri}
        if label is not None:
            out["label"] = label
        out["labels"] = dict(c.labels)
        if definition is not None:
            out["definition"] = definition
        out.update(
            {
                "deprecated": c.deprecated,
                "replacedBy": [e["iri"] for e in self.graph.in_("replaces", iri)],
                "replaces": [e["iri"] for e in self.graph.out("replaces", iri)],
                "layer": c.declared["layer"],
            }
        )
        return out

    def requires(self, iri: str, transitive: bool = False) -> list[dict[str, Any]]:
        """What ``iri`` requires. Transitively, in dependency order: every concept after what it requires; ties by IRI."""
        if not transitive:
            return [self._item(e["iri"], e) for e in self.graph.out("requires", iri)]
        # Depth first and iterative, so a long chain cannot exhaust the recursion limit:
        # each concept is emitted after the concepts it requires.
        out: list[dict[str, Any]] = []
        done = {iri}
        frames: list[tuple[dict[str, Any] | None, Iterator[dict[str, Any]]]] = [
            (None, iter(self.graph.out("requires", iri)))
        ]
        while frames:
            edge, pending = frames[-1]
            e = next(pending, None)
            if e is None:
                frames.pop()
                if edge is not None:
                    out.append(self._item(edge["iri"], edge))
                continue
            if e["iri"] in done:
                continue
            done.add(e["iri"])
            frames.append((e, iter(self.graph.out("requires", e["iri"]))))
        return out

    def required_by(self, iri: str) -> list[dict[str, Any]]:
        return [self._item(e["iri"], e) for e in self.graph.in_("requires", iri)]

    def parts(self, iri: str) -> list[dict[str, Any]]:
        return [self._item(e["iri"], e) for e in self.graph.out("hasPart", iri)]

    def narrower(self, iri: str, transitive: bool = False) -> list[dict[str, Any]]:
        """Narrower concepts; transitively, breadth first (by depth, then IRI)."""
        out: list[dict[str, Any]] = []
        seen = {iri}
        level = [iri]
        while level:
            nxt: list[dict[str, Any]] = []
            for n in level:
                for e in self.graph.in_("broader", n):
                    if e["iri"] in seen:
                        continue
                    seen.add(e["iri"])
                    nxt.append(self._item(e["iri"], e))
            nxt.sort(key=lambda x: utf16_key(x["iri"]))
            out.extend(nxt)
            if not transitive:
                break
            level = [x["iri"] for x in nxt]
        return out

    def broader(self, iri: str) -> list[dict[str, Any]]:
        return [self._item(e["iri"], e) for e in self.graph.out("broader", iri)]

    def related(self, iri: str) -> list[dict[str, Any]]:
        """Related concepts, in both directions."""
        seen: dict[str, dict[str, Any]] = {}
        for e in [*self.graph.out("related", iri), *self.graph.in_("related", iri)]:
            seen.setdefault(e["iri"], e)
        return [self._item(e["iri"], e) for e in js_sorted(seen.values(), key=lambda e: e["iri"])]

    def sequence(self, iri: str) -> list[dict[str, Any]] | None:
        """The members of an ordered collection, in order, or None."""
        c = self.graph.collections.get(iri)
        if c is None:
            return None
        return [self._item(m, c) for m in c["members"]]

    def descendants(self, iri: str) -> list[str]:
        """Every concept below ``iri`` by hierarchy or parts, transitively."""
        out: set[str] = set()
        stack = [iri]
        while stack:
            n = stack.pop()
            for e in [*self.graph.in_("broader", n), *self.graph.out("hasPart", n)]:
                if e["iri"] not in out and e["iri"] != iri:
                    out.add(e["iri"])
                    stack.append(e["iri"])
        return js_sorted(out)

    def nodes(
        self, iri: str, include: str = "none", locale: str | None = None, include_all: bool = False
    ) -> list[CitationRecord]:
        """Citation records of the nodes bound to ``iri`` (and to its narrower concepts or parts, by ``include``).

        The default retrieval policy applies unless ``include_all`` is set. Sorted by node reference.
        """
        wanted = {iri}
        if include != "none":
            stack = [iri]
            while stack:
                n = stack.pop()
                nxt = [
                    *(self.graph.in_("broader", n) if include in ("narrower", "both") else []),
                    *(self.graph.out("hasPart", n) if include in ("parts", "both") else []),
                ]
                for e in nxt:
                    if e["iri"] not in wanted:
                        wanted.add(e["iri"])
                        stack.append(e["iri"])
        records = [
            r
            for r in self.library.citations(locale, include_text=True)
            if any(c in wanted for c in r.get("concepts", [])) and (include_all or passes_default_policy(r))
        ]
        return sorted(records, key=lambda r: utf16_key(r["node"]["ref"]))
