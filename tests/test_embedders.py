"""The standard embedding models. The model test runs when MOCA_TEST_MODELS names a store holding bge-small."""

from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from moca_reader.embedders import (
    ONNX_FILE,
    STANDARD_MODELS,
    find_standard_model,
    installed_models,
    standard_embedder,
)


def test_the_four_standard_models_are_pinned_with_their_convention() -> None:
    assert [m.id for m in STANDARD_MODELS] == [
        "bge-small-en-v1.5",
        "nomic-embed-text-v1.5",
        "all-MiniLM-L6-v2",
        "multilingual-e5-small",
    ]
    for m in STANDARD_MODELS:
        assert len(m.commit) == 40
        assert m.version == "onnx-q8"
        assert ONNX_FILE in m.files
        assert all(len(sha) == 64 for sha in m.files.values())
    model = find_standard_model("BAAI/bge-small-en-v1.5")
    assert model is not None and model.id == "bge-small-en-v1.5"
    assert find_standard_model("nope") is None


def test_a_missing_or_changed_model_is_refused(tmp_path: Path) -> None:
    assert installed_models(tmp_path) == []
    with pytest.raises(FileNotFoundError, match="moca-embed models add all-MiniLM-L6-v2"):
        standard_embedder("all-MiniLM-L6-v2", tmp_path)
    with pytest.raises(ValueError, match="not a standard model"):
        standard_embedder("nope", tmp_path)
    model = find_standard_model("all-MiniLM-L6-v2")
    assert model is not None
    for file in model.files:
        path = tmp_path / model.id / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not the model")
    assert installed_models(tmp_path) == [model]
    with pytest.raises(ValueError, match="does not match"):
        standard_embedder("all-MiniLM-L6-v2", tmp_path)


@pytest.mark.skipif(
    not os.environ.get("MOCA_TEST_MODELS")
    or not (Path(os.environ["MOCA_TEST_MODELS"]) / "bge-small-en-v1.5" / ONNX_FILE).exists(),
    reason="MOCA_TEST_MODELS does not name a store holding bge-small-en-v1.5",
)
def test_bge_small_embeds_with_its_convention() -> None:
    pytest.importorskip("onnxruntime")
    embedder = standard_embedder("bge-small-en-v1.5", os.environ["MOCA_TEST_MODELS"])
    assert (embedder.name, embedder.version, embedder.dimensions) == ("BAAI/bge-small-en-v1.5", "onnx-q8", 384)
    [doc] = embedder.embed(["Customers may request a full refund within 30 days of delivery."])
    [query] = embedder.embed(["how long do I have to get a refund"], "query")
    [other] = embedder.embed(["The engine needs oil checked before each flight."])
    assert math.isclose(math.sqrt(sum(x * x for x in doc)), 1, abs_tol=1e-4)
    assert sum(a * b for a, b in zip(query, doc, strict=True)) > sum(a * b for a, b in zip(query, other, strict=True))
