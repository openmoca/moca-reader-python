"""Runs parity.mjs's scenarios through this Reader and prints the results as JSON, in the reference's shape.

Usage: python tests/parity/run.py <scenarios.json> <moca-spec dir> <sidecar dir>
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime
from typing import Any

from moca_reader import (
    DenseBackend,
    HybridBackend,
    LexicalBackend,
    Library,
    MemoryStoreBackend,
    PackageResult,
    Search,
    StoreScope,
    bind_sidecar,
    diversify,
    package_state,
    read_package,
)
from moca_reader.backends.bm25 import tokens

DIMENSIONS = 64


def fnv1a(text: str) -> int:
    h = 0x811C9DC5
    for byte in text.encode("utf-8"):
        h = ((h ^ byte) * 0x01000193) & 0xFFFFFFFF
    return h


class HashingEmbedder:
    """The deterministic embedder parity.mjs uses: this Reader's tokens, FNV-1a into 64 buckets, counts."""

    def __init__(self, name: str) -> None:
        self.name, self.version, self.dimensions = name, "1", DIMENSIONS
        self.query_prefix = self.document_prefix = None

    def embed(self, texts: list[str], role: str) -> list[list[float]]:
        out = []
        for text in texts:
            v = [0.0] * DIMENSIONS
            for token in tokens(text):
                v[fnv1a(token) % DIMENSIONS] += 1
            out.append(v)
        return out


def main(scenarios: str, spec: str, work: str) -> None:
    with open(scenarios, encoding="utf-8") as f:
        config = json.load(f)
    now = datetime.fromisoformat(config["now"])
    cache: dict[str, PackageResult] = {}
    output = []
    for sc in config["scenarios"]:
        library = Library(clock=lambda: now)
        codes: list[str] = []
        for pair in sc["load"]:
            path = os.path.join(spec, config["packages"][pair[0]])
            if path not in cache:
                cache[path] = read_package(path)
            result = cache[path]
            chunks, index = None, None
            if len(pair) > 1:
                bound = bind_sidecar(os.path.join(work, pair[1]), result)
                codes.extend(d.code for d in bound.diagnostics)
                if bound.usable:
                    chunks, index = bound.chunks, bound.index
            library.add(result, chunks, index)
        embedder = HashingEmbedder("another-model" if sc.get("embedder") == "other" else "parity-hash")
        backend: Any
        if sc["backend"].startswith("store"):
            backend = MemoryStoreBackend(embedder if sc["backend"] == "store-dense" else None).ingest(library)
            search = Search(
                StoreScope([package_state(p.result) for p in library.packages], lambda: now),
                backend,
                audiences=sc.get("audiences"),
            )
        else:
            if sc["backend"] == "dense":
                backend = DenseBackend(library, embedder)
            elif sc["backend"] == "hybrid":
                backend = HybridBackend(
                    LexicalBackend(library),
                    DenseBackend(library, embedder),
                    **({"weights": sc["hybrid"]["weights"]} if "hybrid" in sc else {}),
                )
            else:
                backend = LexicalBackend(library)
            hooks = diversify(sc["diversify"]) if "diversify" in sc else None
            search = Search(library, backend, audiences=sc.get("audiences"), hooks=hooks)
        queries = []
        for q in config["queries"][sc["queries"]]:
            results = []
            for r in search.search(q, limit=config["limit"], locale=sc.get("locale")):
                span = r.get("span")
                results.append(
                    {
                        "ref": r["node"]["ref"],
                        "locale": r["node"].get("locale"),
                        "span": [span["start"], span["end"]] if span else None,
                        "score": r["score"],
                        "text": hashlib.sha256((r.get("text") or "").encode("utf-8")).hexdigest()[:16],
                    }
                )
            queries.append({"query": q, "results": results})
        codes.extend(d.code for d in getattr(backend, "diagnostics", None) or [])
        output.append({"name": sc["name"], "codes": sorted(set(codes)), "queries": queries})
    sys.stdout.write(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main(*sys.argv[1:4])
