"""The MOCA Reader for Python: open, verify, search and cite MOCA packages.

    from moca_reader import read_package, Library

    pkg = read_package("support-kb.moca", trust_root="trust-root.json")
    library = Library().add(pkg)
    for record in library.search("refund window"):
        print(record["node"]["title"], record["node"]["ref"])

Names follow the Reader interface (moca-spec spec/moca-reader-interface.md) in Python's style.
"""

from .attestations import TrustRoot
from .backends.dense import DenseBackend, model_mismatch, similarity
from .backends.hybrid import HybridBackend
from .backends.lexical import LexicalBackend
from .backends.memory_store import MemoryStoreBackend
from .citation import CitationRecord, citation_for, passes_default_policy, pick_representation
from .codes import CODES
from .content import ContentNode, Representation
from .diagnostics import Diagnostic
from .evidence_text import selector_matches
from .library import Library, Overlay
from .metadata import FLAT_FIELDS, flat_metadata
from .profiles import KNOWN_PROFILES, PROFILE_ONTOLOGY
from .reader import MOCA_VERSION, Member, PackageResult, Review, read_package
from .resolver import directory_resolver
from .search import Embedder, HookContext, Search, SearchBackend, SearchHooks, StoreScope
from .sidecar import SidecarBinding, bind_sidecar
from .source import DEFAULT_LIMITS, HostSource, SourceEntry
from .state import package_state
from .strategies.diversify import diversify
from .strategies.ontology_guided import ontology_guided
from .structure import structure_view
from .structure_ops import StructureIndex

__version__ = "0.6.0"

__all__ = [
    "CODES",
    "DEFAULT_LIMITS",
    "FLAT_FIELDS",
    "KNOWN_PROFILES",
    "MOCA_VERSION",
    "PROFILE_ONTOLOGY",
    "CitationRecord",
    "ContentNode",
    "DenseBackend",
    "Diagnostic",
    "Embedder",
    "HookContext",
    "HostSource",
    "HybridBackend",
    "LexicalBackend",
    "Library",
    "Member",
    "MemoryStoreBackend",
    "Overlay",
    "PackageResult",
    "Representation",
    "Review",
    "Search",
    "SearchBackend",
    "SearchHooks",
    "SidecarBinding",
    "SourceEntry",
    "StoreScope",
    "StructureIndex",
    "TrustRoot",
    "bind_sidecar",
    "citation_for",
    "directory_resolver",
    "diversify",
    "flat_metadata",
    "model_mismatch",
    "ontology_guided",
    "package_state",
    "passes_default_policy",
    "pick_representation",
    "read_package",
    "selector_matches",
    "similarity",
    "structure_view",
]
