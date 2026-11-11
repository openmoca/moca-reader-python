"""A reference store backend, kept in memory (Reader contract §9.4).

It stands in for a host's vector store in tests and shows what a store binding must record at ingest: the whole
citation record, including the package digest. Search then resolves hits from those records, so the host never has
to load every package to search its store.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .._js import js_string, round_scaled
from ..audience import record_allowed
from ..citation import citation_for
from ..sidecar import chunk_text
from .bm25 import bm25
from .dense import similarity

if TYPE_CHECKING:
    from ..library import Library
    from ..search import Embedder


class MemoryStoreBackend:
    """Without an embedder the store is searched lexically. ``distance`` is how its vectors are compared."""

    def __init__(
        self, embedder: Embedder | None = None, filter_pushdown: bool = True, distance: str = "cosine"
    ) -> None:
        self.embedder = embedder
        self.distance = distance
        self.features = (
            "dense" if embedder is not None else "lexical",
            *(("filterPushdown",) if filter_pushdown else ()),
        )
        self.diagnostics: list[Any] = []
        self.records: list[dict[str, Any]] = []

    def ingest(self, library: Library) -> MemoryStoreBackend:
        """Ingests every node representation (or sidecar chunk) of every package, through citation records."""
        index = library.relation_index()
        now = library.clock()
        pending: list[dict[str, Any]] = []
        for p in library.packages:
            result = p.result
            by_path = {n.path: n for n in result.nodes}
            units: list[tuple[Any, Any, Any, Any, Any]]
            if p.chunks is not None:
                units = [
                    (by_path.get(c["path"]), c.get("locale") or None, {"start": c["start"], "end": c["end"]}, c, None)
                    for c in p.chunks
                ]
            else:
                units = [
                    (node, rep.locale, None, None, rep.body) for node in result.nodes for rep in node.representations
                ]
            for node, locale, span, chunk, body in units:
                rep = next((r for r in node.representations if (r.locale or None) == locale), None) if node else None
                if node is None or rep is None:
                    continue
                text = chunk_text(chunk, rep) if chunk is not None else body or ""
                record = citation_for(result, node, rep, now, index, text)
                if span is not None:
                    record["span"] = dict(span)
                hit: dict[str, Any] = {"digest": result.digest, "node": record["node"]["id"], "path": node.path}
                if rep.locale:
                    hit["locale"] = rep.locale
                if span is not None:
                    hit["span"] = span
                hit["record"] = record
                entry: dict[str, Any] = {
                    "hit": hit,
                    "text": f"{record['node'].get('title') or ''} {text}",
                    "concepts": record.get("concepts") or [],
                }
                if record.get("audience"):
                    entry["audience"] = record["audience"]
                if record.get("audienceInvalid") is True:
                    entry["audienceInvalid"] = True
                pending.append(entry)
        if self.embedder is not None and pending:
            vectors = self.embedder.embed([e["text"] for e in pending], "document")
            for entry, vector in zip(pending, vectors, strict=True):
                entry["vector"] = vector
        self.records.extend(pending)
        return self

    def remove(self, digest: str) -> MemoryStoreBackend:
        """Removes everything ingested from a package digest."""
        self.records = [r for r in self.records if r["hit"]["digest"] != digest]
        return self

    def search(self, query: str, limit: int, filters: dict[str, Any]) -> list[dict[str, Any]]:
        candidates = self.records
        if "filterPushdown" in self.features:
            digests = set(filters.get("digests") or [])
            excluded = {f"{x['digest']} {x['node']}" for x in filters.get("exclude") or []}
            audiences, concepts = filters.get("audiences"), filters.get("concepts")
            candidates = [
                r
                for r in candidates
                if r["hit"]["digest"] in digests
                and f"{r['hit']['digest']} {r['hit']['node']}" not in excluded
                and record_allowed(r, audiences, filters.get("allowUnlabelled") is True)
                and (not concepts or any(c in concepts for c in r["concepts"]))
            ]
        if self.embedder is None:
            docs = [
                {
                    "item": r["hit"],
                    "text": r["text"],
                    "key": f"{r['hit']['node']}\0{r['hit'].get('locale') or ''}\0{js_string((r['hit'].get('span') or {}).get('start', 0))}",
                }
                for r in candidates
            ]
            return [{**h["item"], "score": h["score"]} for h in bm25(docs, query)[:limit]]
        q = self.embedder.embed([query], "query")[0]
        scored = [
            {**r["hit"], "score": round_scaled(similarity(self.distance, q, r.get("vector")), 1e4)} for r in candidates
        ]
        scored.sort(key=lambda h: -h["score"])
        return scored[:limit]
