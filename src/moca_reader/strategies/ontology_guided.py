"""The default ontology-guided retrieval strategy (moca-spec ADR-0010). Opt-in: pass its hooks to Search.

ingress: when the query names concepts by their label, search those concepts and their descendants.
egress: after each result, add the nodes of the concepts it requires (transitively), tagged retrieval.via = "requires".
The Reader's gate still applies the retrieval policy to everything added.
"""

from __future__ import annotations

import re
from typing import Any

from .._js import js_sorted
from ..search import HookContext, SearchHooks
from ..structure import preferred

_WORD = re.compile(r"[^\W_]+")


def _words(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def ontology_guided(expand_requires: bool = True) -> SearchHooks:
    def ingress(query: str, ctx: HookContext) -> dict[str, Any]:
        if ctx.structure is None:
            return {}
        q = set(_words(query))
        matched = []
        for c in ctx.structure.graph.concepts.values():
            if not c.declared:
                continue
            label = preferred(c.labels)
            w = _words(label) if label else []
            if w and all(x in q for x in w):
                matched.append(c.iri)
        if not matched:
            return {}
        concepts = dict.fromkeys(matched)
        for iri in matched:
            for d in ctx.structure.descendants(iri):
                concepts.setdefault(d)
        return {"concepts": js_sorted(concepts)}

    def egress(candidates: list[dict[str, Any]], ctx: HookContext) -> list[dict[str, Any]]:
        if not expand_requires or ctx.structure is None:
            return candidates
        out: list[dict[str, Any]] = []
        seen = {r["node"]["ref"] for r in candidates}
        for record in candidates:
            out.append(record)
            for concept in record.get("concepts") or []:
                for req in ctx.structure.requires(concept, transitive=True):
                    for node in ctx.structure.nodes(req["iri"], locale=ctx.request.get("locale")):
                        if node["node"]["ref"] in seen:
                            continue
                        seen.add(node["node"]["ref"])
                        out.append(
                            {**node, "score": record.get("score"), "retrieval": {"via": "requires", "from": concept}}
                        )
        return out

    return SearchHooks(ingress=ingress, egress=egress)
