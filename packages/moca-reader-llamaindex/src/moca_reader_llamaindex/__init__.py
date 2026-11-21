"""A LlamaIndex retriever over MOCA packages (Reader interface §7).

``MocaRetriever`` wraps a host-built ``moca_reader.Search``: its backend, audiences and hooks. Every call goes
through the Reader's gate, so the retrieval policy and the host's audience filter always apply, and nothing a
caller passes can widen them. Each citation record becomes a ``NodeWithScore``: a ``TextNode`` with the text, the
whole record under ``metadata["moca_citation"]`` and the consuming guide's flat ``moca_*`` fields beside it, and
the record's score. The MOCA keys are excluded from the text LlamaIndex sends to a model or an embedder.

Package text is untrusted input to a model: pass it to a model as quoted reference material to cite, never as
instructions (Reader contract §12).
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, TypeVar

from llama_index.core.callbacks import CallbackManager
from llama_index.core.retrievers import BaseRetriever
from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode

from moca_reader import CitationRecord, Library, Search, flat_metadata, ingest_terms, terms_request

__all__ = ["MocaRetriever", "ingest", "node_id", "to_node"]
__version__ = "0.7.0"


def node_id(record: CitationRecord) -> str:
    """A unique id: the node's versioned reference, then the byte span, since one node can return several chunks."""
    span = record.get("span")
    ref = str(record["node"]["ref"])
    return f"{ref}:{span['start']}-{span['end']}" if isinstance(span, dict) else ref


def to_node(record: CitationRecord) -> NodeWithScore:
    """A citation record as a LlamaIndex ``NodeWithScore``."""
    metadata: dict[str, Any] = {"moca_citation": record, **flat_metadata(record)}
    keys = list(metadata)
    node = TextNode(
        id_=node_id(record),
        text=record.get("text") or "",
        metadata=metadata,
        excluded_llm_metadata_keys=keys,
        excluded_embed_metadata_keys=keys,
    )
    score = record.get("score")
    return NodeWithScore(node=node, score=float(score) if isinstance(score, (int, float)) else None)


class StoreBackend(Protocol):
    """A store backend's ingest (Reader interface §5.2), such as ``moca_reader.MemoryStoreBackend``'s."""

    def ingest(self, library: Library, terms: dict[str, Any] | None = ..., terms_limits: Any = ...) -> Any: ...


_Store = TypeVar("_Store", bound=StoreBackend)


def ingest(
    store: _Store,
    library: Library,
    *,
    destination: Literal["device", "host", "provider"] = "provider",
    conditions: list[str] | None = None,
    terms_limits: dict[str, Any] | None = None,
) -> _Store:
    """Ingests a library into a store backend with a terms request (Reader contract §9.4): embedding sends content
    to a model, so units whose creator's terms do not allow AI use where the embedder runs are never embedded or
    stored. ``destination`` is where the host's embedder runs: ``"provider"`` (a third party's model) unless the app
    declares ``"device"`` or ``"host"``; ``conditions`` the provider conditions it meets. The store reports U004 for
    what it left out."""
    store.ingest(library, terms=ingest_terms(destination, conditions), terms_limits=terms_limits)
    return store


class MocaRetriever(BaseRetriever):
    """Retrieves citation records from MOCA packages as LlamaIndex ``NodeWithScore``s.

    ``search`` is the host's ``moca_reader.Search``; the other arguments are the search options for every call.

    Nodes go to a model, so every search applies a terms request (Reader contract §15.4): the gate also removes
    records whose creator's terms do not allow AI use at ``destination``. That is ``"provider"`` (a third party's
    model) unless the app declares ``"device"`` (the person's own device) or ``"host"`` (the app's own service).
    ``conditions`` are the provider conditions the app meets (``"noTraining"``, ``"noRetention"``). ``terms`` adds
    to the request, such as a ``rating`` request; an ``ai`` in it is used as it is, and must be an object: the retriever never searches
    without one.
    """

    def __init__(
        self,
        search: Search,
        *,
        limit: int = 5,
        locale: str | None = None,
        concepts: list[str] | None = None,
        scope: str | None = None,
        include_all: bool = False,
        destination: Literal["device", "host", "provider"] = "provider",
        conditions: list[str] | None = None,
        terms: dict[str, Any] | None = None,
        callback_manager: CallbackManager | None = None,
    ) -> None:
        super().__init__(callback_manager=callback_manager)
        self._search = search
        self._options: dict[str, Any] = {
            "limit": limit,
            "include_all": include_all,
            "locale": locale,
            "concepts": concepts,
            "scope": scope,
            "terms": terms_request(destination, conditions, terms),
        }

    def _retrieve(self, query_bundle: QueryBundle) -> list[NodeWithScore]:
        return [to_node(r) for r in self._search.search(query_bundle.query_str, **self._options)]
