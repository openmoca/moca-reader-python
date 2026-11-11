"""MocaRetriever returns citation records as LangChain Documents, through the Reader's gate."""

from __future__ import annotations

import json
from pathlib import Path

from moca_reader_langchain import MocaRetriever

from moca_reader import FLAT_FIELDS, Library, MemoryStoreBackend, Search, StoreScope, package_state
from moca_reader.schemas import validate_against

REFUND = "https://example.com/moca/support-kb@4.2.0#refund-window.md"


def test_documents_carry_text_id_score_and_the_whole_record(public_search: Search) -> None:
    docs = MocaRetriever(search=public_search, limit=3).invoke("How long is the refund window?")
    first = docs[0]
    assert first.metadata["moca_node_ref"] == REFUND
    assert first.id is not None and first.id.startswith(REFUND)
    assert "30 days of delivery" in first.page_content
    assert isinstance(first.metadata["moca_score"], float)
    record = first.metadata["moca_citation"]
    assert validate_against("citationRecord", json.loads(json.dumps(record))) == []
    assert set(first.metadata) - {"moca_citation", "moca_score"} <= set(FLAT_FIELDS)
    assert (first.metadata["moca_signed"], first.metadata["moca_attested_reviews"]) == (True, 1)


def test_the_hosts_audience_filter_holds_whatever_is_asked(public_search: Search) -> None:
    docs = MocaRetriever(search=public_search, limit=20, include_all=True).invoke("delete my account")
    assert all(d.metadata.get("moca_audience") != "internal" for d in docs)


def test_a_store_backend_works_through_the_same_retriever(library: Library) -> None:
    store = MemoryStoreBackend().ingest(library)
    search = Search(StoreScope([package_state(p.result) for p in library.packages], library.clock), store)
    docs = MocaRetriever(search=search, limit=1).invoke("domestic express shipping")
    assert docs[0].metadata["moca_node_ref"].endswith("#shipping-estimates.md")


def test_async_retrieval_returns_the_same(public_search: Search) -> None:
    import asyncio

    retriever = MocaRetriever(search=public_search, limit=2)
    sync = [d.id for d in retriever.invoke("refund window")]
    asynchronous = [d.id for d in asyncio.run(retriever.ainvoke("refund window"))]
    assert sync == asynchronous


def test_the_readme_example_runs(moca_spec: Path, monkeypatch: object) -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text("utf-8")
    code = readme.split("```python\n", 1)[1].split("```", 1)[0]
    import os

    os.chdir(moca_spec / "examples")
    exec(
        compile(
            code.replace('"support-kb.moca"', '"support-kb"').replace(
                '"trust-root.json"', '"../fixtures/signing-keys/trust-root.json"'
            ),
            "README",
            "exec",
        ),
        {},
    )
