"""The structure core (package spec §5.6, moca-spec ADR-0007).

structure.ttl holds a package's concepts and how they relate, using only SKOS and DCMI terms. This module
parses it (and overlays, ADR-0008) into facts, checks node bindings, and builds a sorted JSON view of it
(structure_view). Nothing is fetched: owl:imports and non-absolute IRIs are reported, never followed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import rdflib
from rdflib.plugins.stores.memory import Memory

from ._js import get, js_sorted, utf16_key
from .content import ContentNode, Representation
from .diagnostics import Diagnostics

STRUCTURE_FILE = "structure.ttl"

RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
SKOS = "http://www.w3.org/2004/02/skos/core#"
DCT = "http://purl.org/dc/terms/"
OWL = "http://www.w3.org/2002/07/owl#"
ABSOLUTE_IRI = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.-]*:[^\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+\Z"
)
_PREFIX_DECL = re.compile(
    r"^[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*(?:@prefix|PREFIX)[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+([A-Za-z][A-Za-z0-9_.-]*)?:",
    re.IGNORECASE | re.ASCII | re.MULTILINE,
)
# rdflib resolves relative IRIs against a base; this one marks them, so they are reported as the
# reference Reader reports them: not absolute.
_RELATIVE_BASE = "https://moca-relative.invalid/base/"
_RELATIVE_HOST = "https://moca-relative.invalid/"

PREDICATES: dict[str, tuple[str, bool]] = {
    f"{SKOS}prefLabel": ("label", False),
    f"{SKOS}definition": ("definition", False),
    f"{SKOS}broader": ("broader", False),
    f"{SKOS}narrower": ("broader", True),
    f"{SKOS}related": ("related", False),
    f"{DCT}hasPart": ("hasPart", False),
    f"{DCT}isPartOf": ("hasPart", True),
    f"{DCT}requires": ("requires", False),
    f"{DCT}isRequiredBy": ("requires", True),
    f"{DCT}replaces": ("replaces", False),
    f"{DCT}isReplacedBy": ("replaces", True),
    f"{OWL}deprecated": ("deprecated", False),
}
RELATIONS = ("broader", "related", "hasPart", "requires", "replaces")
LAYERS = ("package", "application", "organisation")

Fact = dict[str, Any]


class _Recorder(Memory):
    """A store that remembers triples in the order the parser states them, as the reference Reader sees them."""

    def __init__(self) -> None:
        super().__init__()
        self.order: list[tuple[Any, Any, Any]] = []

    def add(self, triple: Any, context: Any, quoted: bool = False) -> None:
        self.order.append(triple)
        super().add(triple, context, quoted)


def _iri(term: Any) -> str:
    text = str(term)
    return text[len(_RELATIVE_BASE) :] if text.startswith(_RELATIVE_BASE) else text


def _is_relative(term: Any) -> bool:
    return isinstance(term, rdflib.URIRef) and str(term).startswith(_RELATIVE_HOST)


def parse_structure(
    text: bytes | str, file: str, layer: str, origin: str | None, diagnostics: Diagnostics, limits: dict[str, int]
) -> tuple[list[Fact], set[str], bool]:
    """Parses Turtle into core facts. Unknown predicates are ignored; problems are reported as O codes."""
    before = len(diagnostics.items)
    facts: list[Fact] = []
    prefixes: set[str] = set()
    size = len(text) if isinstance(text, bytes) else len(text.encode("utf-8"))
    if size > limits["maxStructureBytes"]:
        diagnostics.add(
            "O001_ONTOLOGY_UNPARSEABLE", f"{file} is larger than the {limits['maxStructureBytes']}-byte limit", file
        )
        return facts, prefixes, False
    source = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    prefixes.update(m[1] for m in _PREFIX_DECL.finditer(source) if m[1])
    store = _Recorder()
    try:
        rdflib.Graph(store=store).parse(data=source, format="turtle", publicID=_RELATIVE_BASE)
    except Exception as err:  # rdflib raises several types for bad syntax
        diagnostics.add("O001_ONTOLOGY_UNPARSEABLE", f"{file} is not parseable Turtle: {err}", file)
        return facts, prefixes, False
    triples = store.order
    if len(triples) > limits["maxTriples"]:
        diagnostics.add(
            "O001_ONTOLOGY_UNPARSEABLE",
            f"{file} has {len(triples)} triples, over the {limits['maxTriples']} limit",
            file,
        )
        return facts, prefixes, False

    lists: dict[Any, dict[str, Any]] = {}
    for s, p, o in triples:
        if isinstance(s, rdflib.BNode) and str(p) in (f"{RDF}first", f"{RDF}rest"):
            lists.setdefault(s, {})["first" if str(p) == f"{RDF}first" else "rest"] = o

    def add(fact: Fact) -> None:
        facts.append({**fact, "layer": layer, "origin": origin})

    for s, p, o in triples:
        if str(p) == f"{OWL}imports":
            diagnostics.add(
                "O003_REMOTE_REFERENCE", f"owl:imports {_iri(o)} is not allowed; structure must be self-contained", file
            )
        for term in (s, p, o):
            if isinstance(term, rdflib.URIRef) and (_is_relative(term) or not ABSOLUTE_IRI.match(str(term))):
                diagnostics.add("O003_REMOTE_REFERENCE", f"IRI <{_iri(term)}> is not absolute", file)
        if not isinstance(s, rdflib.URIRef):
            continue
        subject = _iri(s)
        predicate = str(p)
        if predicate == f"{RDF}type":
            if str(o) == f"{SKOS}Concept":
                add({"s": subject, "kind": "concept"})
            if str(o) == f"{SKOS}OrderedCollection":
                add({"s": subject, "kind": "collection"})
            continue
        if predicate == f"{SKOS}memberList":
            node: Any = o
            seen: set[Any] = set()
            index = 0
            while node is not None and isinstance(node, rdflib.BNode) and node not in seen:
                seen.add(node)
                cell = lists.get(node)
                if not cell or cell.get("first") is None:
                    break
                if isinstance(cell["first"], rdflib.URIRef):
                    add({"s": subject, "kind": "member", "o": _iri(cell["first"]), "index": index})
                node = cell.get("rest")
                index += 1
            continue
        known = PREDICATES.get(predicate)
        if not known:
            continue
        kind, flip = known
        if kind in ("label", "definition"):
            if isinstance(o, rdflib.Literal):
                add({"s": subject, "kind": kind, "value": str(o), "lang": o.language or ""})
        elif kind == "deprecated":
            if isinstance(o, rdflib.Literal) and str(o) == "true":
                add({"s": subject, "kind": kind})
        elif isinstance(o, rdflib.URIRef):
            add({"s": _iri(o), "kind": kind, "o": subject} if flip else {"s": subject, "kind": kind, "o": _iri(o)})
    ok = not any(d.code.startswith("O") for d in diagnostics.items[before:])
    return facts, prefixes, ok


@dataclass
class Concept:
    iri: str
    declared: dict[str, Any] | None
    labels: dict[str, str]
    definitions: dict[str, str]
    deprecated: bool = False


class StructureGraph:
    """An index over facts from any number of layers. The first layer to state a fact is the one reported."""

    def __init__(self, facts: list[Fact]) -> None:
        self.facts = sorted(facts, key=lambda f: LAYERS.index(f["layer"]))
        self.concepts: dict[str, Concept] = {}
        self.collections: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, dict[str, dict[str, Any]]]] = {k: {} for k in RELATIONS}
        self.inverse: dict[str, dict[str, dict[str, dict[str, Any]]]] = {k: {} for k in RELATIONS}

        def concept(iri: str) -> Concept:
            if iri not in self.concepts:
                self.concepts[iri] = Concept(iri, None, {}, {})
            return self.concepts[iri]

        def edge(table: dict[str, dict[str, dict[str, Any]]], s: str, o: str, f: Fact) -> None:
            targets = table.setdefault(s, {})
            if o not in targets:
                targets[o] = {"layer": f["layer"], "origin": f["origin"]}

        members: dict[str, dict[int, str]] = {}
        for f in self.facts:
            kind = f["kind"]
            if kind == "concept":
                c = concept(f["s"])
                if not c.declared:
                    c.declared = {"layer": f["layer"], "origin": f["origin"]}
            elif kind in ("collection", "member"):
                if f["s"] not in self.collections:
                    self.collections[f["s"]] = {
                        "iri": f["s"],
                        "layer": f["layer"],
                        "origin": f["origin"],
                        "members": [],
                    }
                    members[f["s"]] = {}
                if kind == "member":
                    c2 = self.collections[f["s"]]
                    slots = members[f["s"]]
                    if c2["origin"] == f["origin"] and f["o"] not in slots.values():
                        slots[f["index"]] = f["o"]
            elif kind == "label":
                c = concept(f["s"])
                c.labels.setdefault(f["lang"], f["value"])
            elif kind == "definition":
                c = concept(f["s"])
                c.definitions.setdefault(f["lang"], f["value"])
            elif kind == "deprecated":
                concept(f["s"]).deprecated = True
            elif kind in RELATIONS:
                edge(self.edges[kind], f["s"], f["o"], f)
                edge(self.inverse[kind], f["o"], f["s"], f)
        for iri, c3 in self.collections.items():
            c3["members"] = [m for _, m in sorted(members[iri].items()) if m]

    def out(self, kind: str, iri: str) -> list[dict[str, Any]]:
        """IRIs a relation points to from ``iri``, sorted, with the layer that stated each."""
        return js_sorted(({"iri": o, **at} for o, at in self.edges[kind].get(iri, {}).items()), key=lambda e: e["iri"])

    def in_(self, kind: str, iri: str) -> list[dict[str, Any]]:
        return js_sorted(
            ({"iri": s, **at} for s, at in self.inverse[kind].get(iri, {}).items()), key=lambda e: e["iri"]
        )

    def is_declared(self, iri: str) -> bool:
        c = self.concepts.get(iri)
        return bool(c and c.declared) or iri in self.collections

    def cycle(self, kind: str) -> list[str] | None:
        """The first cycle found in a relation, as a list of IRIs, or None."""
        state: dict[str, int] = {}
        for start in js_sorted(self.edges[kind]):
            if start in state:
                continue
            stack = [start]
            state[start] = 1
            pending = [iter(self.out(kind, start))]
            while pending:
                nxt = next(pending[-1], None)
                if nxt is None:
                    state[stack.pop()] = 2
                    pending.pop()
                    continue
                target = nxt["iri"]
                if state.get(target) == 1:
                    return [*stack[stack.index(target) :], target]
                if target not in state:
                    state[target] = 1
                    stack.append(target)
                    pending.append(iter(self.out(kind, target)))
        return None


def preferred(values: dict[str, str]) -> str | None:
    """Preferred label: no language tag, then ``en``, then the first language in order."""
    if "" in values:
        return values[""]
    if "en" in values:
        return values["en"]
    langs = js_sorted(values)
    return values[langs[0]] if langs else None


def structure_view(graph: StructureGraph) -> dict[str, Any]:
    """A JSON view of the structure, sorted so any two Readers produce the same bytes. Not a package file (moca-spec ADR-0019)."""
    concepts = []
    for c in sorted((c for c in graph.concepts.values() if c.declared), key=lambda c: utf16_key(c.iri)):
        label, definition = preferred(c.labels), preferred(c.definitions)

        def ids(kind: str, iri: str = c.iri) -> list[str]:
            return [e["iri"] for e in graph.out(kind, iri)]

        entry: dict[str, Any] = {"iri": c.iri}
        if label is not None:
            entry["label"] = label
        if definition is not None:
            entry["definition"] = definition
        if c.deprecated:
            entry["deprecated"] = True
        related = js_sorted(dict.fromkeys([*ids("related"), *(e["iri"] for e in graph.in_("related", c.iri))]))
        entry.update(
            {
                "broader": ids("broader"),
                "related": related,
                "parts": ids("hasPart"),
                "requires": ids("requires"),
                "replaces": ids("replaces"),
            }
        )
        concepts.append(entry)
    sequences = [
        {"iri": c["iri"], "members": list(c["members"])}
        for c in sorted(graph.collections.values(), key=lambda c: utf16_key(c["iri"]))
    ]
    return {"structureVersion": 1, "concepts": concepts, "sequences": sequences}


@dataclass
class PackageStructure:
    present: bool
    ok: bool
    facts: list[Fact]
    graph: StructureGraph | None


def read_structure(
    data: dict[str, bytes],
    nodes: list[ContentNode],
    diagnostics: Diagnostics,
    limits: dict[str, int],
    origin: str | None,
) -> PackageStructure:
    """Parses structure.ttl, checks node bindings, and sets each representation's concepts."""
    ttl = data.get(STRUCTURE_FILE)
    bound: list[Representation] = [
        r for n in nodes for r in n.representations if isinstance(get(r.frontmatter.get("moca"), "concepts"), list)
    ]
    if ttl is None and not bound:
        return PackageStructure(False, False, [], None)
    before = len(diagnostics.items)

    if ttl is None:
        for rep in bound:
            diagnostics.add(
                "O002_CONCEPT_UNDECLARED", f"concepts are bound but the package has no {STRUCTURE_FILE}", rep.file
            )
        return PackageStructure(False, False, [], None)

    facts, prefixes, _ = parse_structure(ttl, STRUCTURE_FILE, "package", origin, diagnostics, limits)
    graph = StructureGraph(facts)
    for kind in ("requires", "broader", "hasPart"):
        loop = graph.cycle(kind)
        if loop:
            diagnostics.add("O005_STRUCTURE_CYCLE", f"{kind} forms a cycle: {' -> '.join(loop)}", STRUCTURE_FILE)
    referenced: set[str] = set()
    for kind in RELATIONS:
        for s, targets in graph.edges[kind].items():
            referenced.add(s)
            referenced.update(targets)
    for c in graph.collections.values():
        referenced.update(c["members"])
    for iri in js_sorted(referenced):
        if not graph.is_declared(iri):
            diagnostics.add(
                "O002_CONCEPT_UNDECLARED",
                f"{iri} is used in a relation but not declared as a skos:Concept",
                STRUCTURE_FILE,
            )

    for rep in bound:
        concepts: list[str] = []
        for b in rep.frontmatter["moca"]["concepts"]:
            iri = get(b, "iri")
            if not isinstance(iri, str) or not ABSOLUTE_IRI.match(iri):
                diagnostics.add("O003_REMOTE_REFERENCE", f'concept "{iri}" is not an absolute IRI', rep.file)
                continue
            if iri[: iri.index(":")] in prefixes and not graph.is_declared(iri):
                diagnostics.add(
                    "O003_REMOTE_REFERENCE", f'concept "{iri}" is a prefixed name; write the absolute IRI', rep.file
                )
                continue
            if not graph.is_declared(iri):
                diagnostics.add(
                    "O002_CONCEPT_UNDECLARED", f"concept {iri} is not declared in {STRUCTURE_FILE}", rep.file
                )
            concepts.append(iri)
        if concepts:
            rep.concepts = list(dict.fromkeys(concepts))

    ok = not any(d.code.startswith("O") for d in diagnostics.items[before:])
    return PackageStructure(True, ok, facts, graph)
