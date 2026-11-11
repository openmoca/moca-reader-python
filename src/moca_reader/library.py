"""A library of loaded packages: citation records, relations between packages, and their merged structure with
the host's overlays (Reader contract §7-§10). Search over a library is in search.py."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ._js import get, js_string
from .citation import CitationRecord, RelationIndex, citation_for, pick_representation
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

    def add(self, result: PackageResult, chunks: list[dict[str, Any]] | None = None, index: Any = None) -> Library:
        """Adds a package read by read_package(), with a bound sidecar's chunks and index. Invalid packages are refused."""
        if not result.valid or not result.digest:
            raise ValueError(f"refusing to add an invalid package: {get(result.manifest, 'id') or '(unknown)'}")
        key = _key(result)
        same = next((p for p in self.packages if _key(p.result) == key), None)
        if same is not None:
            # Contract §7: one id@version, one digest. A second digest is refused and reported.
            if same.result.digest != result.digest:
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
        audiences: list[str] | None = None,
        allow_unlabelled: bool = False,
    ) -> list[CitationRecord]:
        """Lexical search over the loaded packages; a shortcut for ``Search(library, LexicalBackend(library))``."""
        from .backends.lexical import LexicalBackend
        from .search import Search

        return Search(self, LexicalBackend(self), audiences=audiences, allow_unlabelled=allow_unlabelled).search(
            query, limit=limit, include_all=include_all, locale=locale, concepts=concepts, scope=scope
        )


def _key(result: PackageResult) -> str:
    return f"{js_string(result.manifest.get('id'))}@{js_string(result.manifest.get('version'))}"
