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

from typing import Any

from llama_index.core.callbacks import CallbackManager
from llama_index.core.retrievers import BaseRetriever
from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode

from moca_reader import CitationRecord, Search, flat_metadata

__all__ = ["MocaRetriever", "node_id", "to_node"]
__version__ = "0.6.0"


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


class MocaRetriever(BaseRetriever):
    """Retrieves citation records from MOCA packages as LlamaIndex ``NodeWithScore``s.

    ``search`` is the host's ``moca_reader.Search``; the other arguments are the search options for every call.
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
        }

    def _retrieve(self, query_bundle: QueryBundle) -> list[NodeWithScore]:
        return [to_node(r) for r in self._search.search(query_bundle.query_str, **self._options)]
