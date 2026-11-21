"""A library of loaded packages: citation records, relations between packages, and their merged structure with
the host's overlays (Reader contract §7-§10). Search over a library is in search.py."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ._js import get, js_string, utf16_key
from .audience import record_allowed
from .citation import CitationRecord, RelationIndex, citation_for, passes_default_policy, pick_representation
from .diagnostics import Diagnostics
from .relations import relation_index_of
from .source import DEFAULT_LIMITS
from .structure import LAYERS, Fact, parse_structure

if TYPE_CHECKING:
    from .reader import PackageResult
    from .structure_ops import StructureIndex


@dataclass(frozen=True)
class Overlay:
    """Host-supplied structure (moca-spec ADR-0008), never package content: Turtle text or a file."""

    id: str
    layer: str  # application | organisation
    source: str | bytes | None = None
    path: str | os.PathLike[str] | None = None


@dataclass
class LoadedPackage:
    result: PackageResult
    chunks: list[dict[str, Any]] | None = None
    index: Any = None


class Library:
    """Holds verified packages, with their sidecar chunks when bound."""

    def __init__(
        self,
        clock: Callable[[], datetime] | None = None,
        overlays: list[Overlay] | None = None,
        limits: dict[str, int] | None = None,
        allow_unsigned_relations: bool = False,
    ) -> None:
        self.clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))
        # Package spec §7.2: off by default. Only for libraries of the host's own packages.
        self.allow_unsigned_relations = allow_unsigned_relations
        self.packages: list[LoadedPackage] = []
        self.diagnostics = Diagnostics()
        self.overlay_facts: list[Fact] = []
        limit_values = {**DEFAULT_LIMITS, **(limits or {})}
        for o in overlays or []:
            if o.layer not in ("application", "organisation"):
                raise ValueError(f"overlay {o.id}: layer must be application or organisation")
            text: str | bytes
            if o.source is not None:
                text = o.source
            elif o.path is not None:
                with open(o.path, "rb") as f:
                    text = f.read()
            else:
                raise ValueError(f"overlay {o.id}: give its source or its path")
            facts, _, _ = parse_structure(
                text, f"overlay:{o.id}", o.layer, f"overlay:{o.id}", self.diagnostics, limit_values
            )
            self.overlay_facts.extend(facts)
        self.overlay_facts.sort(key=lambda f: LAYERS.index(f["layer"]))
        self._structure: StructureIndex | None = None

    @property
    def structure(self) -> StructureIndex:
        """The merged structure of every loaded package and overlay (Reader contract §10)."""
        from .structure_ops import StructureIndex

        if self._structure is None:
            self._structure = StructureIndex(self, self.overlay_facts)
        return self._structure

    def structure_for(self, terms: Any = None, terms_limits: Any = None) -> StructureIndex:
        """The structure operations for a host that hands their answers to a model (Reader contract §10, "Under a
        terms request"; moca-spec ADR-0041): the merged structure of the loaded packages that are not closed for the
        request, and the overlays. A request with no ``ai`` part closes nothing, so it is the whole structure."""
        from .structure_ops import StructureIndex
        from .terms_gate import library_resolver

        if not isinstance(terms, dict) or not isinstance(terms.get("ai"), (dict, list)):
            return self.structure
        resolver = library_resolver(self, _limits(terms_limits), terms)
        open_packages = [p for p in self.packages if not resolver.closure(p.result.digest)["closed"]]
        return StructureIndex(self, self.overlay_facts, open_packages)

    def catalogue(
        self,
        terms: Any = None,
        audiences: list[str] | None = None,
        allow_unlabelled: bool = False,
        include_all: bool = False,
        terms_limits: Any = None,
    ) -> list[dict[str, Any]]:
        """What a model may be told about the loaded packages (Reader contract §15.4, "The catalogue rule";
        moca-spec ADR-0041), ordered by id then version.

        A package has an entry only when one of its records, or of its members' at any depth, passes the audience
        set and (unless ``include_all``) the default retrieval policy; when its own rating passes the request's
        rating gate; and when it is not hidden. A closed package's entry has exactly id, version, title, publisher,
        signed and closedBy. Each entry is valid against catalogue-entry.schema.json.
        """
        from .terms import gate_reasons
        from .terms_gate import library_resolver

        request = terms if isinstance(terms, dict) else None
        resolver = library_resolver(self, _limits(terms_limits), request)
        index = self.relation_index()
        now = self.clock()
        own: dict[str, bool] = {}

        def passes_own(result: PackageResult) -> bool:
            digest = result.digest or ""
            if digest not in own:
                own[digest] = any(
                    (include_all or passes_default_policy(r)) and record_allowed(r, audiences, allow_unlabelled is True)
                    for node in result.nodes
                    for rep in node.representations
                    for r in (citation_for(result, node, rep, now, index),)
                )
            return own[digest]

        def passes(result: PackageResult) -> bool:
            # Its own records, or those of a member it composes, at any depth; each package walked once.
            seen: set[str] = set()
            queue = [result]
            while queue:
                r = queue.pop(0)
                if r.digest in seen:
                    continue
                seen.add(r.digest or "")
                if passes_own(r):
                    return True
                queue += [
                    m.result
                    for m in r.members
                    if m.status == "resolved" and m.result is not None and m.result.valid and m.result.digest
                ]
            return False

        listed: list[tuple[PackageResult, dict[str, Any]]] = []
        ordered = sorted(
            (p.result for p in self.packages),
            key=lambda r: (utf16_key(js_string(r.manifest.get("id"))), utf16_key(js_string(r.manifest.get("version")))),
        )
        for result in ordered:
            if not passes(result):
                continue
            if request is not None and "rating" in request:
                # The package's own rating, never a node's, as a record with that rating would be gated.
                declared = (result.terms or {}).get("declared")
                rating = declared.get("rating", None) if isinstance(declared, dict) else None
                if isinstance(declared, dict) and "rating" in declared and rating is None:
                    rating = False
                if gate_reasons({"rating": request["rating"]}, {}, rating):
                    continue
            closure = resolver.closure(result.digest)
            if closure["hidden"]:
                continue
            listed.append((result, closure))
        present = {f"{r.manifest.get('id')}@{r.manifest.get('version')}" for r, _ in listed}
        return [_entry(result, closure, present) for result, closure in listed]

    def add(self, result: PackageResult, chunks: list[dict[str, Any]] | None = None, index: Any = None) -> Library:
        """Adds a package read by read_package(), with a bound sidecar's chunks and index. Invalid packages are refused."""
        if not result.valid or not result.digest:
            raise ValueError(f"refusing to add an invalid package: {get(result.manifest, 'id') or '(unknown)'}")
        key = _key(result)
        same = next((p for p in self.packages if _key(p.result) == key), None)
        if same is not None:
            # Contract §7: one id@version, one digest. A second digest is refused and reported.
            if same.result.digest != result.digest:
                # Package spec §13.5: a second issued copy of the same original is expected, and only noted.
                original = (same.result.issued_copy or {}).get("originalDigest")
                if original and original == (result.issued_copy or {}).get("originalDigest"):
                    self.diagnostics.add(
                        "L002_ISSUED_COPY_DUPLICATE",
                        f"{key} is already loaded as another issued copy of {original}; {result.digest} is not loaded",
                    )
                else:
                    self.diagnostics.add(
                        "L001_IDENTITY_CONFLICT",
                        f"{key} is already loaded with digest {same.result.digest}; {result.digest} is refused",
                    )
            return self
        self.packages.append(LoadedPackage(result, chunks, index))
        self._structure = None
        # A composed package brings its verified members with it.
        for member in result.members:
            if member.status == "resolved" and member.result is not None and member.result.valid:
                self.add(member.result)
        return self

    def relation_index(self) -> RelationIndex:
        """Package-level relation effects among the loaded packages (package spec §7.2)."""
        return relation_index_of(
            [
                {
                    "id": p.result.manifest.get("id"),
                    "version": p.result.manifest.get("version"),
                    "relations": p.result.manifest.get("relations"),
                    "relationScopes": p.result.relation_scopes,
                }
                for p in self.packages
            ],
            self.allow_unsigned_relations,
        )

    def citations(self, locale: str | None = None, include_text: bool = False) -> list[CitationRecord]:
        """Citation records for every node: one per node, in the requested locale."""
        index = self.relation_index()
        now = self.clock()
        out = []
        for p in self.packages:
            for node in p.result.nodes:
                rep = pick_representation(node, locale)
                out.append(citation_for(p.result, node, rep, now, index, rep.body if include_text else None))
        return out

    def get(self, node_ref: str, locale: str | None = None, include_text: bool = True) -> CitationRecord | None:
        """A node by its id (``<package id>#<path>``) or versioned reference (``<package id>@<version>#<path>``).

        An id matches the first loaded version.
        """
        hash_at = node_ref.rfind("#")
        if hash_at < 0:
            return None
        path, head = node_ref[hash_at + 1 :], node_ref[:hash_at]
        index = self.relation_index()
        for p in self.packages:
            pid, version = js_string(p.result.manifest.get("id")), js_string(p.result.manifest.get("version"))
            if head not in (pid, f"{pid}@{version}"):
                continue
            node = next((n for n in p.result.nodes if n.path == path), None)
            if node is None:
                continue
            rep = pick_representation(node, locale)
            return citation_for(p.result, node, rep, self.clock(), index, rep.body if include_text else None)
        return None

    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        include_all: bool = False,
        locale: str | None = None,
        concepts: list[str] | None = None,
        scope: str | None = None,
        up_to: str | None = None,
        audiences: list[str] | None = None,
        allow_unlabelled: bool = False,
        terms: dict[str, Any] | None = None,
        terms_limits: dict[str, Any] | None = None,
    ) -> list[CitationRecord]:
        """Lexical search over the loaded packages; a shortcut for ``Search(library, LexicalBackend(library))``.

        ``terms`` is the host's terms request and ``terms_limits`` its own ``ai`` values (contract §15.4), as for
        ``Search``: without a request, terms remove nothing. A host that hands the records to a model passes one
        (``terms_request``)."""
        from .backends.lexical import LexicalBackend
        from .search import Search

        search = Search(
            self,
            LexicalBackend(self),
            audiences=audiences,
            allow_unlabelled=allow_unlabelled,
            terms_limits=terms_limits,
        )
        return search.search(
            query,
            limit=limit,
            include_all=include_all,
            locale=locale,
            concepts=concepts,
            scope=scope,
            up_to=up_to,
            terms=terms,
        )


def _limits(terms_limits: Any) -> Any:
    from .terms import UNSET

    return terms_limits if isinstance(terms_limits, (dict, list)) else UNSET


def _entry(result: PackageResult, closure: dict[str, Any], present: set[str]) -> dict[str, Any]:
    """A catalogue entry (contract §15.4): a closed package's has exactly id, version, title, publisher, signed and
    closedBy; an open package's adds what the manifest has of description and tags, and its members that have an
    entry of their own."""
    m = result.manifest
    name = (result.publisher or {}).get("name")
    publisher = {"publisher": name} if isinstance(name, str) else {}
    signed = len(result.signers) > 0
    if closure["closed"]:
        return {
            "id": m.get("id"),
            "version": m.get("version"),
            "title": m.get("title"),
            **publisher,
            "signed": signed,
            "closedBy": list(closure["closedBy"]),
        }
    entry: dict[str, Any] = {"id": m.get("id"), "version": m.get("version"), "title": m.get("title")}
    if isinstance(m.get("description"), str):
        entry["description"] = m["description"]
    entry.update(publisher)
    entry["signed"] = signed
    if isinstance(result.tags, list):
        entry["tags"] = list(result.tags)
    members = m.get("members")
    if isinstance(members, list) and members:
        entry["members"] = [
            x["id"]
            for x in members
            if isinstance(x, dict)
            and isinstance(x.get("id"), str)
            and isinstance(x.get("version"), str)
            and f"{x['id']}@{x['version']}" in present
        ]
    return entry


def _key(result: PackageResult) -> str:
    return f"{js_string(result.manifest.get('id'))}@{js_string(result.manifest.get('version'))}"
