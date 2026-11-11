"""Dense backend over sidecar vectors (Reader contract §9.3), scored by the index's ``model.distance`` (cosine by
default). The host supplies the embedder. Every loaded package it does not search is reported: a sidecar whose model
does not match the embedder (S006), or no vectors at all (S007)."""

from __future__ import annotations

import json
import math
from typing import TYPE_CHECKING, Any

from .._js import get, js_string, round_scaled, truthy
from ..audience import audience_allowed, audience_of
from ..citation import pick_representation
from ..diagnostics import Diagnostics

if TYPE_CHECKING:
    from ..library import Library
    from ..search import Embedder


class DenseBackend:
    features = ("dense", "filterPushdown")

    def __init__(self, library: Library, embedder: Embedder) -> None:
        if embedder is None or not callable(getattr(embedder, "embed", None)):
            raise TypeError("DenseBackend needs a host embedder")
        self.library = library
        self.embedder = embedder
        self._checks = Diagnostics()
        self.diagnostics = self._checks.items
        self.checked: dict[str, bool] = {}
        self._check()

    def search(self, query: str, limit: int, filters: dict[str, Any]) -> list[dict[str, Any]]:
        self._check()
        digests = filters.get("digests")
        usable = [
            p
            for p in self.library.packages
            if self.checked.get(p.result.digest or "") and (digests is None or p.result.digest in digests)
        ]
        if not usable:
            return []
        q = self.embedder.embed([query], "query")[0]
        excluded = {f"{x['digest']} {x['node']}" for x in filters.get("exclude") or []}
        audiences, concepts, locale = filters.get("audiences"), filters.get("concepts"), filters.get("locale")
        scored: list[dict[str, Any]] = []
        for p in usable:
            result = p.result
            distance = get(get(p.index, "model"), "distance")
            by_path = {n.path: n for n in result.nodes}
            for c in p.chunks or []:
                node = by_path.get(c["path"])
                rep = (
                    next((r for r in node.representations if (r.locale or None) == (c.get("locale") or None)), None)
                    if node
                    else None
                )
                if node is None or rep is None or not isinstance(c.get("vector"), list):
                    continue
                node_id = f"{js_string(result.manifest.get('id'))}#{node.path}"
                if f"{result.digest} {node_id}" in excluded:
                    continue
                if locale and pick_representation(node, locale) is not rep:
                    continue
                label, invalid = audience_of(node, rep)
                if not audience_allowed(label, invalid, audiences, filters.get("allowUnlabelled") is True):
                    continue
                if concepts and not any(x in concepts for x in rep.concepts or []):
                    continue
                hit: dict[str, Any] = {"digest": result.digest, "node": node_id, "path": node.path}
                if rep.locale:
                    hit["locale"] = rep.locale
                hit["span"] = {"start": c["start"], "end": c["end"]}
                hit["score"] = round_scaled(similarity(distance, q, c["vector"]), 1e4)
                scored.append(hit)
        scored.sort(key=lambda h: -h["score"])
        return scored[:limit]

    def _check(self) -> None:
        """Compares the embedder with each loaded sidecar's model, once per package digest."""
        for p in self.library.packages:
            digest = p.result.digest or ""
            if digest in self.checked:
                continue
            vectors = [c for c in p.chunks or [] if isinstance(c.get("vector"), list)]
            name = f"{js_string(p.result.manifest.get('id'))}@{js_string(p.result.manifest.get('version'))}"
            if not truthy(p.index) or not vectors:
                self._checks.add("S007_NO_VECTORS", f"{name}: no sidecar vectors; the package is not searched")
                self.checked[digest] = False
                continue
            problem = model_mismatch(self.embedder, get(p.index, "model"), len(vectors[0]["vector"]))
            if problem:
                self._checks.add("S006_MODEL_MISMATCH", f"{name}: {problem}")
            self.checked[digest] = not problem


def model_mismatch(embedder: Any, model: Any, vector_length: int) -> str | None:
    """Why an embedder cannot search vectors made by ``model``, or None when it can."""
    name = get(model, "name")
    if not truthy(name):
        return "the index names no model"
    if name != embedder.name:
        return f'index model "{name}" is not the host embedder "{embedder.name}"'
    version, own_version = model.get("version"), getattr(embedder, "version", None)
    if truthy(version) and truthy(own_version) and version != own_version:
        return f"index model version {version} is not {own_version}"
    dims = model["dimensions"] if model.get("dimensions") is not None else vector_length
    if dims != embedder.dimensions:
        return f"index has {dims} dimensions; the host embedder has {embedder.dimensions}"
    # Prefixes are compared, never applied (Reader contract §9.3).
    for key, attr in (("queryPrefix", "query_prefix"), ("documentPrefix", "document_prefix")):
        theirs, ours = model.get(key), getattr(embedder, attr, None)
        # A prefix declared on one side only is a mismatch too.
        if theirs != ours:
            return f"index {key} {json.dumps(theirs, ensure_ascii=False)} is not the host embedder's {json.dumps(ours, ensure_ascii=False)}"
    return None


def similarity(distance: Any, a: Any, b: Any) -> float:
    """How well vector ``b`` matches query ``a``: cosine (the default), the dot product, or the negative euclidean
    distance. A higher score is always a better match."""
    if not isinstance(a, list) or not isinstance(b, list) or len(a) != len(b):
        return 0.0
    if distance == "dot":
        total = 0.0
        for x, y in zip(a, b, strict=True):
            total += x * y
        return total
    if distance == "euclidean":
        squares = 0.0
        for x, y in zip(a, b, strict=True):
            squares += (x - y) ** 2
        return 0 - math.sqrt(squares)
    return cosine(a, b)


def cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = na = nb = 0.0
    for x, y in zip(a, b, strict=True):
        dot += x * y
        na += x * x
        nb += y * y
    return 0.0 if na == 0 or nb == 0 else dot / math.sqrt(na * nb)
