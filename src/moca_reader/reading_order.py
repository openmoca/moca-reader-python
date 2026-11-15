"""Package spec §4.10 and Reader contract §9: the reading order, and the search option upTo."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ._js import js_sorted

if TYPE_CHECKING:
    from .structure import StructureGraph


@dataclass(frozen=True)
class ReadingOrder:
    """The members of the ordered collection a manifest names, and each concept's position on it."""

    iri: str
    members: tuple[str, ...]
    positions: dict[str, int]

    def to_state(self) -> dict[str, Any]:
        """Plain JSON for a package state (contract §9.4): positions keyed by concept IRI."""
        return {
            "iri": self.iri,
            "members": list(self.members),
            "positions": dict(js_sorted(self.positions.items(), key=lambda kv: kv[0])),
        }

    @staticmethod
    def from_state(state: Any) -> ReadingOrder | None:
        if not isinstance(state, dict) or not isinstance(state.get("members"), list):
            return None
        positions = state.get("positions")
        if not isinstance(positions, dict):
            return None
        return ReadingOrder(str(state.get("iri")), tuple(state["members"]), dict(positions))


def resolve_reading_order(graph: StructureGraph | None, iri: str) -> ReadingOrder | None:
    """The reading order ``iri`` names in a package's own graph; None when it does not resolve (M014).

    A concept's position is the index of the first member that is the concept, or has it as a descendant by narrower
    or hasPart.
    """
    collection = graph.collections.get(iri) if graph is not None else None
    if graph is None or not collection or not collection.get("typed") or not collection["members"]:
        return None
    # Contract §3: one walk in list order, with one visited set. A concept first reached from member i keeps i, as it
    # would if each member were walked on its own, and nothing is walked twice.
    positions: dict[str, int] = {}
    for i, member in enumerate(collection["members"]):
        stack = [member]
        while stack:
            n = stack.pop()
            if n in positions:
                continue
            positions[n] = i
            stack.extend(
                e["iri"] for e in [*graph.in_("broader", n), *graph.out("hasPart", n)] if e["iri"] not in positions
            )
    return ReadingOrder(iri, tuple(collection["members"]), positions)


def passes_up_to(record: dict[str, Any], order: ReadingOrder | None, up_to: str) -> bool:
    """Contract §9: whether a record passes upTo. It is placed as any concept is, so a descendant limits as the first
    member that contains it. A package whose reading order does not place it is not limited, nor is a record bound to
    no concept on it."""
    if order is None or up_to not in order.positions:
        return True
    limit = order.positions[up_to]
    return all(c not in order.positions or order.positions[c] <= limit for c in record.get("concepts") or [])
