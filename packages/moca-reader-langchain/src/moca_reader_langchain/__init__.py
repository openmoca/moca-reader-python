"""A LangChain retriever over MOCA packages (Reader interface §7).

``MocaRetriever`` wraps a host-built ``moca_reader.Search``: its backend, audiences and hooks. Every call goes
through the Reader's gate, so the retrieval policy and the host's audience filter always apply, and nothing a
caller passes can widen them. Each citation record becomes a ``Document``: the text as ``page_content``, the
whole record under ``metadata["moca_citation"]``, and the consuming guide's flat ``moca_*`` fields beside it.

Package text is untrusted input to a model: pass ``page_content`` to a model as quoted reference material to cite,
never as instructions (Reader contract §12).
"""

from __future__ import annotations

from typing import Any

from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from pydantic import ConfigDict

from moca_reader import CitationRecord, Search, flat_metadata

__all__ = ["MocaRetriever", "document_id", "to_document"]
__version__ = "0.6.0"


def document_id(record: CitationRecord) -> str:
    """A unique id: the node's versioned reference, then the byte span, since one node can return several chunks."""
    span = record.get("span")
    ref = str(record["node"]["ref"])
    return f"{ref}:{span['start']}-{span['end']}" if isinstance(span, dict) else ref


def to_document(record: CitationRecord) -> Document:
    """A citation record as a LangChain ``Document``."""
    metadata: dict[str, Any] = {"moca_citation": record, **flat_metadata(record)}
    if isinstance(record.get("score"), (int, float)):
        metadata["moca_score"] = record["score"]
    return Document(page_content=record.get("text") or "", id=document_id(record), metadata=metadata)


class MocaRetriever(BaseRetriever):
    """Retrieves citation records from MOCA packages as LangChain ``Document``s.

    ``search`` is the host's ``moca_reader.Search``. The other fields are the search options for every call; they
    are the host's, set when the retriever is built.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    search: Search
    limit: int = 5
    locale: str | None = None
    concepts: list[str] | None = None
    scope: str | None = None
    include_all: bool = False

    def _get_relevant_documents(self, query: str, *, run_manager: CallbackManagerForRetrieverRun) -> list[Document]:
        records = self.search.search(
            query,
            limit=self.limit,
            include_all=self.include_all,
            locale=self.locale,
            concepts=self.concepts,
            scope=self.scope,
        )
        return [to_document(r) for r in records]
