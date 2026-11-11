"""moca-spec's runner protocol (conformance/README.md): one JSON object ``{root, case}`` on stdin, one JSON result
on stdout. What this Reader concludes for one case of conformance/cases.json. It ships with the package, so the
corpus runs against the Reader you installed. From a moca-spec checkout:

    node scripts/run-conformance.mjs --reader "python -m moca_reader.conformance"
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from datetime import datetime
from typing import Any

from . import (
    DenseBackend,
    HybridBackend,
    LexicalBackend,
    Library,
    MemoryStoreBackend,
    Overlay,
    Search,
    SearchHooks,
    StoreScope,
    bind_sidecar,
    directory_resolver,
    ontology_guided,
    read_package,
)
from .state import package_state

UNLOADED = "sha256:" + "0" * 64


class ConformanceEmbedder:
    """The identity a case names, and [1, 0, 0, ...] for every text, whatever the role."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.name = spec["name"]
        self.version = spec.get("version")
        self.dimensions = spec["dimensions"]
        self.query_prefix = spec.get("queryPrefix")
        self.document_prefix = spec.get("documentPrefix")

    def embed(self, texts: list[str], role: str) -> list[list[float]]:
        return [[1.0 if i == 0 else 0.0 for i in range(self.dimensions)] for _ in texts]


class EveryHitBackend:
    """Ignores every filter, declares no features, and returns every representation plus one unknown digest."""

    features: tuple[str, ...] = ()

    def __init__(self, library: Library) -> None:
        self.library = library

    def search(self, query: str, limit: int, filters: dict[str, Any]) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for p in self.library.packages:
            for node in p.result.nodes:
                for rep in node.representations:
                    hit = {
                        "digest": p.result.digest,
                        "node": f"{p.result.manifest['id']}#{node.path}",
                        "path": node.path,
                    }
                    if rep.locale:
                        hit["locale"] = rep.locale
                    hits.append({**hit, "score": 1})
        hits.append({"digest": UNLOADED, "node": "https://example.com/not-loaded#x.md", "path": "x.md", "score": 2})
        return hits


def hostile_hooks() -> SearchHooks:
    """An egress hook that tries to return everything, plus a record from a package that is not loaded."""

    def egress(candidates: list[dict[str, Any]], ctx: Any) -> list[dict[str, Any]]:
        everything = ctx.library.citations(include_text=True)
        fake = [{**everything[0], "package": {**everything[0]["package"], "digest": UNLOADED}}] if everything else []
        return [*candidates, *everything, *fake]

    return SearchHooks(egress=egress)


def hostile_ingress_hooks() -> SearchHooks:
    """An ingress hook that asks for more than the caller did: the gate must follow the caller."""
    return SearchHooks(ingress=lambda query, ctx: {"includeAll": True, "limit": 1000, "locale": "fr"})


def concept_item(x: dict[str, Any] | None) -> dict[str, Any] | None:
    if x is None:
        return None
    out = {"iri": x["iri"]}
    if "label" in x:
        out["label"] = x["label"]
    out["layer"] = x["layer"]
    return out


def actual_for(root: str, c: dict[str, Any]) -> dict[str, Any]:
    o = c.get("options") or {}
    read_options: dict[str, Any] = {
        "trust_root": os.path.join(root, o["trustRoot"]) if o.get("trustRoot") else None,
        "resolve_member": directory_resolver([os.path.join(root, m) for m in o["members"]])
        if o.get("members")
        else None,
        "limits": o.get("limits"),
        # The host clock applies to reading too: keys expire (attestations §6).
        "clock": (lambda: datetime.fromisoformat(o["now"])) if o.get("now") else None,
        "require_signature": o.get("requireSignature") is True,
        "strict": o.get("strict") is True,
    }
    overlays = [Overlay(v["id"], v["layer"], path=os.path.join(root, v["path"])) for v in o.get("overlays") or []]

    if c.get("kind") == "structure":
        library = Library(overlays=overlays)
        for target in c["packages"]:
            result = read_package(os.path.join(root, target), **read_options)
            if result.valid:
                library.add(result)
        s = library.structure
        a = c.get("args") or {}
        iri = c["iri"]
        ops: dict[str, Callable[[], Any]] = {
            "concept": lambda: s.concept(iri),
            "requires": lambda: [concept_item(x) for x in s.requires(iri, transitive=a.get("transitive", False))],
            "requiredBy": lambda: [concept_item(x) for x in s.required_by(iri)],
            "parts": lambda: [concept_item(x) for x in s.parts(iri)],
            "narrower": lambda: [concept_item(x) for x in s.narrower(iri, transitive=a.get("transitive", False))],
            "broader": lambda: [concept_item(x) for x in s.broader(iri)],
            "related": lambda: [concept_item(x) for x in s.related(iri)],
            "sequence": lambda: None if (seq := s.sequence(iri)) is None else [concept_item(x) for x in seq],
            "nodes": lambda: [r["node"]["ref"] for r in s.nodes(iri, include=a.get("include", "none"))],
        }
        return {"codes": [d.code for d in library.diagnostics.items], "result": ops[c["op"]]()}

    if c.get("kind") == "search":
        now = datetime.fromisoformat(o["now"])
        library = Library(
            clock=lambda: now, overlays=overlays, allow_unsigned_relations=o.get("allowUnsignedRelations") is True
        )
        codes: list[str] = []
        for target in c["packages"]:
            result = read_package(os.path.join(root, target), **read_options)
            if not result.valid:
                continue
            chunks, index = None, None
            if o.get("sidecar"):
                bound = bind_sidecar(os.path.join(root, o["sidecar"]), result)
                codes.extend(d.code for d in bound.diagnostics)
                if bound.usable:
                    chunks, index = bound.chunks, bound.index
            library.add(result, chunks, index)
        hooks = (
            hostile_hooks()
            if o.get("hooks") == "hostile"
            else hostile_ingress_hooks()
            if o.get("hooks") == "hostile-ingress"
            else ontology_guided()
            if o.get("hooks") == "ontology-guided"
            else None
        )
        s = c["search"]
        options = {
            "limit": s.get("limit", 50),
            "include_all": s.get("includeAll", False),
            "locale": s.get("locale"),
            "concepts": s.get("concepts"),
            "scope": s.get("scope"),
        }
        if o.get("backend") == "store":
            # Everything listed is ingested (each package on its own with `ingestSeparately`); only the packages
            # in `allow` are "loaded", and the search gets their package states (contract §9.4).
            store = MemoryStoreBackend(filter_pushdown=False)
            if o.get("ingestSeparately"):
                for p in library.packages:
                    single = Library(clock=lambda: now)
                    single.add(p.result)
                    store.ingest(single)
            else:
                store.ingest(library)
            allow = {os.path.join(root, t) for t in o.get("allow") or []}
            allowed = [
                package_state(p.result)
                for p in library.packages
                if p.result.source and p.result.source.location in allow
            ]
            records = Search(
                StoreScope(allowed, lambda: now, o.get("allowUnsignedRelations") is True),
                store,
                audiences=o.get("audiences"),
                allow_unlabelled=o.get("allowUnlabelled") is True,
            ).search(s["query"], **options)
            return {"codes": codes, "records": records}

        def dense() -> DenseBackend:
            return DenseBackend(library, ConformanceEmbedder(o["embedder"]))

        backend: Any
        if o.get("backend") == "all":
            backend = EveryHitBackend(library)
        elif o.get("backend") == "dense":
            backend = dense()
        elif o.get("backend") == "hybrid":
            h = o.get("hybrid") or {}
            backend = HybridBackend(LexicalBackend(library), dense(), k=h.get("k", 60), weights=h.get("weights"))
        else:
            backend = LexicalBackend(library)
        codes.extend(d.code for d in getattr(backend, "diagnostics", None) or [])
        # Library diagnostics (L): for example two digests for one id@version.
        codes.extend(d.code for d in library.diagnostics.items if d.code.startswith("L"))
        records = Search(
            library,
            backend,
            audiences=o.get("audiences"),
            hooks=hooks,
            allow_unlabelled=o.get("allowUnlabelled") is True,
        ).search(s["query"], **options)
        return {"codes": codes, "records": records}

    result = read_package(os.path.join(root, c["target"]), **read_options)
    codes = [d.code for d in result.diagnostics]
    sidecar_usable = None
    if o.get("sidecar"):
        bound = bind_sidecar(os.path.join(root, o["sidecar"]), result)
        codes.extend(d.code for d in bound.diagnostics)
        sidecar_usable = bound.usable
    evidence_matched: dict[str, list[Any]] = {}
    if result.valid:
        for r in Library().add(result).citations():
            if r["evidence"]:
                evidence_matched[r["node"]["path"]] = [e.get("matched") for e in r["evidence"]]
    out: dict[str, Any] = {
        "valid": result.valid,
        "codes": codes,
        "capabilities": result.capabilities,
        "digest": result.digest,
        "evidenceMatched": evidence_matched,
    }
    if sidecar_usable is not None:
        out["sidecarUsable"] = sidecar_usable
    return out


if __name__ == "__main__":
    request = json.loads(sys.stdin.read())
    sys.stdout.write(json.dumps(actual_for(request["root"], request["case"]), ensure_ascii=False))
