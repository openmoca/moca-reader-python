"""An opt-in strategy that spreads results across nodes (moca-spec ADR-0010).

egress: keep each node's best ``per_node`` records in their ranked order, then the rest after them. Nothing is
dropped, so the limit still fills. A node is its versioned reference, so its locales count as one node.
"""

from __future__ import annotations

from typing import Any

from ..search import HookContext, SearchHooks


def diversify(per_node: int = 1) -> SearchHooks:
    if isinstance(per_node, bool) or not isinstance(per_node, int) or per_node < 1:
        raise ValueError("per_node must be a positive integer")

    def egress(candidates: list[dict[str, Any]], ctx: HookContext) -> list[dict[str, Any]]:
        counts: dict[str, int] = {}
        first: list[dict[str, Any]] = []
        rest: list[dict[str, Any]] = []
        for record in candidates:
            n = counts.get(record["node"]["ref"], 0)
            counts[record["node"]["ref"]] = n + 1
            (first if n < per_node else rest).append(record)
        return [*first, *rest]

    return SearchHooks(egress=egress)
