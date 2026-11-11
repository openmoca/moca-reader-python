"""Lexical (BM25) backend over the packages in a library: each package's sidecar chunks when it was added with them,
otherwise its nodes. With a locale, the representation package spec §5 selects for it; without one, every
representation, so content in any language can be found, and the best-scoring one for each node is returned."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .._js import js_string
from ..audience import audience_allowed, audience_of
from ..citation import citation_for, pick_representation
from ..sidecar import chunk_text
from .bm25 import bm25_counted, count_terms

if TYPE_CHECKING:
    from ..library import Library


class LexicalBackend:
    features = ("lexical", "filterPushdown")

    def __init__(self, library: Library) -> None:
        self.library = library
        self.diagnostics: list[Any] = []
        # Each document's term counts, per package digest, kept after its first search and dropped when the package
        # leaves the library; scores are the same as counting afresh.
        self._counted: dict[str, dict[str, tuple[dict[str, int], int]]] = {}

    def search(self, query: str, limit: int, filters: dict[str, Any]) -> list[dict[str, Any]]:
        excluded = {f"{x['digest']} {x['node']}" for x in filters.get("exclude") or []}
        digests = set(filters["digests"]) if filters.get("digests") is not None else None
        audiences, concepts, locale = filters.get("audiences"), filters.get("concepts"), filters.get("locale")
        docs: list[dict[str, Any]] = []
        loaded = {p.result.digest or "" for p in self.library.packages}
        for gone in [d for d in self._counted if d not in loaded]:
            del self._counted[gone]
        for p in self.library.packages:
            result = p.result
            if digests is not None and result.digest not in digests:
                continue
            counted = self._counted.setdefault(result.digest or "", {})
            by_path = {n.path: n for n in result.nodes}
            pid = js_string(result.manifest.get("id"))

            def keep(node: Any, rep: Any, pid: str = pid, digest: Any = result.digest) -> str | None:
                node_id = f"{pid}#{node.path}"
                if f"{digest} {node_id}" in excluded:
                    return None
                label, invalid = audience_of(node, rep)
                if not audience_allowed(label, invalid, audiences, filters.get("allowUnlabelled") is True):
                    return None
                if concepts and not any(c in concepts for c in rep.concepts or []):
                    return None
                return node_id

            if p.chunks is not None:
                for c in p.chunks:
                    node = by_path.get(c["path"])
                    rep = (
                        next((r for r in node.representations if (r.locale or None) == (c.get("locale") or None)), None)
                        if node
                        else None
                    )
                    if node is None or rep is None:
                        continue
                    if locale and pick_representation(node, locale) is not rep:
                        continue
                    node_id = keep(node, rep)
                    if not node_id:
                        continue
                    key = f"{node_id}\0{js_string(c['start']).rjust(12, '0')}"
                    # The cache key adds the locale: chunks of two representations can start at the same offset.
                    cache_key = f"{key}\0{c.get('locale') or ''}"
                    if cache_key not in counted:
                        title = citation_for(result, node, rep)["node"].get("title") or ""
                        counted[cache_key] = count_terms(f"{title} {chunk_text(c, rep)}")
                    item: dict[str, Any] = {"digest": result.digest, "node": node_id, "path": node.path}
                    if rep.locale:
                        item["locale"] = rep.locale
                    item["span"] = {"start": c["start"], "end": c["end"]}
                    docs.append({"item": item, "counts": counted[cache_key], "key": key})
            else:
                for node in result.nodes:
                    reps = [pick_representation(node, locale)] if locale else node.representations
                    for rep in reps:
                        node_id = keep(node, rep)
                        if not node_id:
                            continue
                        key = f"{node_id}\0{rep.locale or ''}"
                        if key not in counted:
                            fm = rep.frontmatter
                            tags = fm["tags"] if isinstance(fm.get("tags"), list) else []
                            parts = [fm.get("title"), fm.get("description"), *tags, rep.body]
                            counted[key] = count_terms(" ".join(x for x in parts if isinstance(x, str)))
                        item = {"digest": result.digest, "node": node_id, "path": node.path}
                        if rep.locale:
                            item["locale"] = rep.locale
                        docs.append({"item": item, "counts": counted[key], "key": key})
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for hit in bm25_counted(docs, query):
            item = hit["item"]
            if "span" not in item:
                # Node ids repeat across versions of a package, so key on the digest too.
                key = f"{item['digest']} {item['node']}"
                if key in seen:
                    continue
                seen.add(key)
            out.append({**item, "score": hit["score"]})
            if len(out) >= limit:
                break
        return out
