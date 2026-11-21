"""MocaRetriever returns citation records as LlamaIndex scored nodes, through the Reader's gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from llama_index.core.schema import MetadataMode
from moca_reader_llamaindex import MocaRetriever, ingest

from moca_reader import FLAT_FIELDS, LexicalBackend, Library, MemoryStoreBackend, Search, read_package
from moca_reader.schemas import validate_against

REFUND = "https://example.com/moca/support-kb@4.2.0#refund-window.md"


def test_nodes_carry_text_id_score_and_the_whole_record(public_search: Search) -> None:
    nodes = MocaRetriever(public_search, limit=3).retrieve("How long is the refund window?")
    first = nodes[0]
    assert first.node.metadata["moca_node_ref"] == REFUND
    assert first.node.node_id.startswith(REFUND)
    assert "30 days of delivery" in first.node.get_content()
    assert isinstance(first.score, float) and first.score > 0
    record = first.node.metadata["moca_citation"]
    assert validate_against("citationRecord", json.loads(json.dumps(record))) == []
    assert set(first.node.metadata) - {"moca_citation"} <= set(FLAT_FIELDS)


def test_moca_metadata_stays_out_of_what_a_model_or_embedder_sees(public_search: Search) -> None:
    node = MocaRetriever(public_search, limit=1).retrieve("refund window")[0].node
    for mode in (MetadataMode.LLM, MetadataMode.EMBED):
        content = node.get_content(metadata_mode=mode)
        assert "moca_" not in content
        assert "30 days of delivery" in content


def test_the_hosts_audience_filter_holds_whatever_is_asked(public_search: Search) -> None:
    nodes = MocaRetriever(public_search, limit=20, include_all=True).retrieve("delete my account")
    assert all(n.node.metadata.get("moca_audience") != "internal" for n in nodes)


def test_the_readme_example_runs(moca_spec: Path) -> None:
    import os

    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text("utf-8")
    code = readme.split("```python\n", 1)[1].split("```", 1)[0]
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
    nodes = MocaRetriever(search, limit=10).retrieve("refunds")
    assert [n.node.metadata["moca_citation"]["node"]["path"] for n in nodes] == ["public.md"]
    on_host = MocaRetriever(search, limit=10, destination="host").retrieve("refunds")
    assert sorted(n.node.metadata["moca_citation"]["node"]["path"] for n in on_host) == ["private.md", "public.md"]
    with pytest.raises(ValueError, match="destination"):
        MocaRetriever(search, destination="moon")  # type: ignore[arg-type]


def test_the_hosts_rating_request_is_added(public_search: Search) -> None:
    assert MocaRetriever(public_search, terms={"rating": {"explicit": False}}).retrieve("refund window") == []
    nodes = MocaRetriever(public_search).retrieve("refund window")
    assert nodes[0].node.metadata["moca_citation"]["terms"]["ai"]["allowed"]["provider"]["value"] is True


def test_a_caller_can_never_drop_the_ai_part(tmp_path: Path) -> None:
    search = _terms_search(tmp_path / "p")
    for dropped in (None, False, [], "none"):
        with pytest.raises(ValueError, match="must be an object"):
            MocaRetriever(search, terms={"ai": dropped})


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
