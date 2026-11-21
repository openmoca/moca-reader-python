"""MocaRetriever returns citation records as LangChain Documents, through the Reader's gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from moca_reader_langchain import MocaRetriever, ingest

from moca_reader import (
    FLAT_FIELDS,
    LexicalBackend,
    Library,
    MemoryStoreBackend,
    Search,
    StoreScope,
    package_state,
    read_package,
)
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


def _terms_search(root: Path) -> Search:
    """A package whose terms keep one node away from third parties' models."""
    root.mkdir()
    terms = {"nodes": [{"paths": ["content/private.md"], "ai": {"allowed": {"provider": False}}}]}
    manifest = {"id": "https://example.com/t", "version": "1.0.0", "title": "T", "terms": terms}
    (root / "moca.json").write_text(json.dumps(manifest))
    (root / "content").mkdir()
    for name in ("public", "private"):
        (root / "content" / f"{name}.md").write_text(f"---\ntype: Note\ntitle: {name}\n---\n\nRefunds, {name}.\n")
    library = Library().add(read_package(str(root)))
    return Search(library, LexicalBackend(library))


def test_terms_apply_by_default_for_a_third_partys_model(tmp_path: Path) -> None:
    search = _terms_search(tmp_path / "p")
    paths = [
        d.metadata["moca_citation"]["node"]["path"] for d in MocaRetriever(search=search, limit=10).invoke("refunds")
    ]
    assert paths == ["public.md"]
    assert search.diagnostics[0].code == "U004_TERMS_EXCLUDED"
    on_device = MocaRetriever(search=search, limit=10, destination="device").invoke("refunds")
    assert sorted(d.metadata["moca_citation"]["node"]["path"] for d in on_device) == ["private.md", "public.md"]


def test_the_hosts_rating_request_is_added(public_search: Search) -> None:
    assert MocaRetriever(search=public_search, terms={"rating": {"explicit": False}}).invoke("refund window") == []
    docs = MocaRetriever(search=public_search).invoke("refund window")
    assert docs[0].metadata["moca_citation"]["terms"]["ai"]["allowed"]["provider"]["value"] is True


def test_a_caller_can_never_drop_the_ai_part(tmp_path: Path) -> None:
    search = _terms_search(tmp_path / "p")
    for dropped in (None, False, [], "none"):
        with pytest.raises(ValueError, match="must be an object"):
            MocaRetriever(search=search, terms={"ai": dropped})


class _Recording:
    name = "recording"
    dimensions = 2

    def __init__(self) -> None:
        self.seen: list[str] = []

    def embed(self, texts: list[str], role: str) -> list[list[float]]:
        self.seen += texts
        return [[1.0, 0.0] for _ in texts]


def test_ingest_passes_a_terms_request_defaulting_to_provider(tmp_path: Path) -> None:
    library = _terms_search(tmp_path / "p").library
    assert library is not None
    embedder = _Recording()
    store = ingest(MemoryStoreBackend(embedder), library)
    assert [r["hit"]["path"] for r in store.records] == ["public.md"]
    assert not any("private" in t for t in embedder.seen)
    assert [d.code for d in store.ingest_diagnostics] == ["U004_TERMS_EXCLUDED"]
    assert len(ingest(MemoryStoreBackend(), library, destination="device").records) == 2
    with pytest.raises(ValueError, match="destination"):
        ingest(MemoryStoreBackend(), library, destination="moon")  # type: ignore[arg-type]
