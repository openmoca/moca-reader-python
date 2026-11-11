"""MocaRetriever returns citation records as LlamaIndex scored nodes, through the Reader's gate."""

from __future__ import annotations

import json
from pathlib import Path

from llama_index.core.schema import MetadataMode
from moca_reader_llamaindex import MocaRetriever

from moca_reader import FLAT_FIELDS, Search
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
