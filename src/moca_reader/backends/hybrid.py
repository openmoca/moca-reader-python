"""Hybrid backend: a lexical and a dense backend merged by Reciprocal Rank Fusion (Reader contract §9.6).

    score(hit) = sum of weight_b / (k + rank_b(hit))

rank_b is the hit's 1-based position in backend b's results. k (default 60) and the weights (default 1) are the
host's; a package never sets them. A package the dense backend cannot search (S006, S007) still comes back through
the lexical side.
"""

from __future__ import annotations

import math
import sys
from typing import Any

from .._js import round_scaled, utf16_key


def _key(h: dict[str, Any]) -> str:
    span = h.get("span") or {}
    return (
        f"{h.get('digest')}\0{h.get('node')}\0{h.get('locale') or ''}\0{span.get('start', '')}\0{span.get('end', '')}"
    )


def _tie(h: dict[str, Any]) -> tuple[bytes, bytes, float]:
    """Ties: node id, then locale, then span start; the same order in every Reader."""
    return utf16_key(str(h.get("node"))), utf16_key(h.get("locale") or ""), (h.get("span") or {}).get("start", -1)


def _weight(name: str, w: Any) -> float:
    if isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w) or w < 0:
        raise ValueError(f"weights.{name} must be a number of at least 0")
    return float(w)


class HybridBackend:
    def __init__(self, lexical: Any, dense: Any, k: float = 60, weights: dict[str, float] | None = None) -> None:
        if not callable(getattr(lexical, "search", None)) or not callable(getattr(dense, "search", None)):
            raise TypeError("HybridBackend needs a lexical and a dense backend")
        if isinstance(k, bool) or not isinstance(k, (int, float)) or not math.isfinite(k) or k < 0:
            raise ValueError("k must be a number of at least 0")
        self.lexical, self.dense, self.k = lexical, dense, k
        w = weights or {}
        self.weights = {
            "lexical": _weight("lexical", w.get("lexical", 1)),
            "dense": _weight("dense", w.get("dense", 1)),
        }
        if self.weights["lexical"] == 0 and self.weights["dense"] == 0:
            raise ValueError("at least one weight must be above 0")
        pushdown = all("filterPushdown" in (getattr(b, "features", None) or []) for b in (lexical, dense))
        self.features = ("lexical", "dense", *(("filterPushdown",) if pushdown else ()))
        self._latest: tuple[dict[str, Any], str, list[dict[str, Any]]] | None = None

    @property
    def diagnostics(self) -> list[Any]:
        """Both backends' findings, such as S006 and S007 from the dense side."""
        return [*(getattr(self.lexical, "diagnostics", None) or []), *(getattr(self.dense, "diagnostics", None) or [])]

    def search(self, query: str, limit: int, filters: dict[str, Any]) -> list[dict[str, Any]]:
        # One search call passes the same filters each time it asks for more (contract §9.2).
        latest = self._latest
        if latest is None or latest[0] is not filters or latest[1] != query:
            latest = self._latest = (filters, query, self._fuse(query, filters or {}))
        return latest[2][:limit]

    def _fuse(self, query: str, filters: dict[str, Any]) -> list[dict[str, Any]]:
        """Contract §9.2, §9.6: ranks are positions in each backend's whole ranking before any filter, so filters never
        change a score; filters pushed down only decide which fused hits pass."""
        unfiltered: dict[str, Any] = {"digests": filters.get("digests"), "exclude": []}
        lexical = self.lexical.search(query, sys.maxsize, unfiltered)
        dense = self.dense.search(query, sys.maxsize, unfiltered)
        passing: set[str] | None = None
        if "filterPushdown" in self.features and any(
            k != "digests" and v not in (None, [], False) for k, v in filters.items()
        ):
            filtered = [
                *(self.lexical.search(query, sys.maxsize, filters) or []),
                *(self.dense.search(query, sys.maxsize, filters) or []),
            ]
            passing = {_key(h) for h in filtered}
        fused: dict[str, dict[str, Any]] = {}

        def add(hits: Any, weight: float) -> None:
            if weight == 0 or not isinstance(hits, list):
                return
            for i, hit in enumerate(hits):
                entry = fused.setdefault(_key(hit), {"hit": hit, "score": 0.0})
                entry["score"] += weight / (self.k + i + 1)

        add(lexical, self.weights["lexical"])
        add(dense, self.weights["dense"])
        ranked = sorted(
            (e for e in fused.values() if e["score"] > 0 and (passing is None or _key(e["hit"]) in passing)),
            key=lambda e: (-e["score"], _tie(e["hit"])),
        )
        return [{**e["hit"], "score": round_scaled(e["score"], 1e6)} for e in ranked]
