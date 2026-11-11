"""MOCA's standard embedding models (sidecar index specification §5.1), run locally, as Reader embedders.

An index built with one of them (``moca-index build --model``) and a question embedded with the same one match,
whichever tool did each: this Reader, the TypeScript and .NET Readers, or the MOCA MCP server. Each model is a local
ONNX file pinned by Hugging Face commit and SHA-256, run with the convention every tool shares: the role's prefix, the
model's own tokenizer cut as Hugging Face's Python tokenizer cuts (the start token, the first tokens that fit, the end
token), one text per run (the 8-bit files quantize activations per run), then CLS or mean pooling and unit length.

The files live in a model store, one folder per model: ``~/.moca/models``, or ``MOCA_MODELS``. This module never
downloads: install a model with ``npx @openmoca/moca-embed models add <model>`` or ``moca-mcp models add <model>``.
It needs the ``onnx`` extra: ``pip install "moca-reader[onnx]"``.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ONNX_FILE = "onnx/model_quantized.onnx"


@dataclass(frozen=True)
class StandardModel:
    """One standard model: its short id, the name and version an index records, and how it is run."""

    id: str
    name: str
    version: str
    dimensions: int
    pooling: str
    max_tokens: int
    query_prefix: str
    document_prefix: str
    repository: str
    commit: str
    licence: str
    files: dict[str, str] = field(default_factory=dict)


STANDARD_MODELS: tuple[StandardModel, ...] = (
    StandardModel(
        "bge-small-en-v1.5",
        "BAAI/bge-small-en-v1.5",
        "onnx-q8",
        384,
        "cls",
        512,
        "Represent this sentence for searching relevant passages: ",
        "",
        "Xenova/bge-small-en-v1.5",
        "ea104dacec62c0de699686887e3f920caeb4f3e3",
        "MIT",
        {
            "vocab.txt": "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3",
            "config.json": "fa73f90bf92c8cace1fbcb709626306f2bdbc9ea3e5b5f94b440df9b6aa56350",
            "tokenizer.json": "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66",
            "tokenizer_config.json": "9261e7d79b44c8195c1cada2b453e55b00aeb81e907a6664974b4d7776172ab3",
            "special_tokens_map.json": "b6d346be366a7d1d48332dbc9fdf3bf8960b5d879522b7799ddba59e76237ee3",
            ONNX_FILE: "6c9c6101a956d62dfb5e7190c538226c0c5bb9cb27b651234b6df063ee7dbfe4",
        },
    ),
    StandardModel(
        "nomic-embed-text-v1.5",
        "nomic-ai/nomic-embed-text-v1.5",
        "onnx-q8",
        768,
        "mean",
        2048,
        "search_query: ",
        "search_document: ",
        "nomic-ai/nomic-embed-text-v1.5",
        "e9b6763023c676ca8431644204f50c2b100d9aab",
        "Apache-2.0",
        {
            "vocab.txt": "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3",
            "config.json": "9ab00bd92cee80a569f708140b7b6c1661a65891ff3765b1519e181ba2f2c92b",
            "tokenizer.json": "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66",
            "tokenizer_config.json": "d7e0000bcc80134debd2222220427e6bf5fa20a669f40a0d0d1409cc18e0a9bc",
            "special_tokens_map.json": "5d5b662e421ea9fac075174bb0688ee0d9431699900b90662acd44b2a350503a",
            ONNX_FILE: "b4342336debaea79de872370664b0aaeb67dea4605513d00ee236ea871a81f27",
        },
    ),
    StandardModel(
        "all-MiniLM-L6-v2",
        "sentence-transformers/all-MiniLM-L6-v2",
        "onnx-q8",
        384,
        "mean",
        256,
        "",
        "",
        "Xenova/all-MiniLM-L6-v2",
        "751bff37182d3f1213fa05d7196b954e230abad9",
        "Apache-2.0",
        {
            "vocab.txt": "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3",
            "config.json": "7135149f7cffa1a573466c6e4d8423ed73b62fd2332c575bf738a0d033f70df7",
            "tokenizer.json": "da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0",
            "tokenizer_config.json": "9261e7d79b44c8195c1cada2b453e55b00aeb81e907a6664974b4d7776172ab3",
            "special_tokens_map.json": "b6d346be366a7d1d48332dbc9fdf3bf8960b5d879522b7799ddba59e76237ee3",
            ONNX_FILE: "afdb6f1a0e45b715d0bb9b11772f032c399babd23bfc31fed1c170afc848bdb1",
        },
    ),
    StandardModel(
        "multilingual-e5-small",
        "intfloat/multilingual-e5-small",
        "onnx-q8",
        384,
        "mean",
        512,
        "query: ",
        "passage: ",
        "Xenova/multilingual-e5-small",
        "761b726dd34fb83930e26aab4e9ac3899aa1fa78",
        "MIT",
        {
            "sentencepiece.bpe.model": "cfc8146abe2a0488e9e2a0c56de7952f7c11ab059eca145a0a727afce0db2865",
            "config.json": "cb99455288675345e1a4f411438d5d0adbba5fbd3a67ea4fb03c015433b996c1",
            "tokenizer.json": "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
            "tokenizer_config.json": "a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b",
            "special_tokens_map.json": "d05497f1da52c5e09554c0cd874037a083e1dc1b9cfd48034d1c717f1afc07a7",
            ONNX_FILE: "f80102d3f2a1229f387d3c81909990d8945513e347b0eab049f7de3c6f98c193",
        },
    ),
)


def default_model_store() -> Path:
    """``MOCA_MODELS``, else ``~/.moca/models``."""
    configured = os.environ.get("MOCA_MODELS")
    return Path(configured) if configured else Path.home() / ".moca" / "models"


def find_standard_model(id_or_name: str) -> StandardModel | None:
    """A standard model by short id (any case) or recorded name."""
    return next((m for m in STANDARD_MODELS if m.id.lower() == id_or_name.lower() or m.name == id_or_name), None)


def installed_models(store: str | os.PathLike[str] | None = None) -> list[StandardModel]:
    """The standard models whose files are all present in a store (not yet checked)."""
    root = Path(store) if store is not None else default_model_store()
    return [m for m in STANDARD_MODELS if all((root / m.id / f).exists() for f in m.files)]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require(id_or_name: str) -> StandardModel:
    model = find_standard_model(id_or_name)
    if model is None:
        raise ValueError(f"not a standard model: {id_or_name} ({', '.join(m.id for m in STANDARD_MODELS)})")
    return model


class StandardEmbedder:
    """A standard model as a Reader embedder: ``embed(texts, role)`` with role ``"query"`` or ``"document"``."""

    def __init__(self, model: StandardModel, folder: Path) -> None:
        try:
            import numpy as np
            import onnxruntime  # type: ignore[import-untyped,import-not-found,unused-ignore]
            from tokenizers import Tokenizer  # type: ignore[import-not-found,unused-ignore]
        except ImportError as error:  # pragma: no cover - depends on the environment
            raise ImportError('the standard models need the onnx extra: pip install "moca-reader[onnx]"') from error
        self._np: Any = np
        self.model = model
        self.name = model.name
        self.version = model.version
        self.dimensions = model.dimensions
        self.query_prefix = model.query_prefix
        self.document_prefix = model.document_prefix
        self._tokenizer: Any = Tokenizer.from_file(str(folder / "tokenizer.json"))
        self._tokenizer.no_truncation()
        self._tokenizer.no_padding()
        options = onnxruntime.SessionOptions()
        options.graph_optimization_level = onnxruntime.GraphOptimizationLevel.ORT_ENABLE_ALL
        self._session: Any = onnxruntime.InferenceSession(
            str(folder / ONNX_FILE), options, providers=["CPUExecutionProvider"]
        )

    def embed(self, texts: Sequence[str], role: str = "document") -> list[list[float]]:
        prefix = self.query_prefix if role == "query" else self.document_prefix
        return [self._embed_one(prefix + text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        np = self._np
        ids = self._tokenizer.encode(text).ids
        if len(ids) > self.model.max_tokens:
            ids = [*ids[: self.model.max_tokens - 1], ids[-1]]
        shape = (1, len(ids))
        inputs = {
            "input_ids": np.array(ids, dtype=np.int64).reshape(shape),
            "attention_mask": np.ones(shape, dtype=np.int64),
            "token_type_ids": np.zeros(shape, dtype=np.int64),
        }
        hidden: Any = self._session.run(None, inputs)[0][0].astype(np.float64)
        vector = hidden[0] if self.model.pooling == "cls" else hidden.mean(axis=0)
        norm = float(np.linalg.norm(vector))
        result: list[float] = (vector / norm if norm > 0 else vector).astype(np.float32).tolist()
        return result


def standard_embedder(id_or_name: str, store: str | os.PathLike[str] | None = None) -> StandardEmbedder:
    """Loads a standard model from a store, after checking each file against its pinned SHA-256."""
    model = _require(id_or_name)
    folder = (Path(store) if store is not None else default_model_store()) / model.id
    for file, expected in model.files.items():
        path = folder / file
        if not path.exists():
            raise FileNotFoundError(
                f"{model.id} is not installed in {folder.parent}: run: npx @openmoca/moca-embed models add {model.id}"
            )
        if _sha256(path) != expected:
            raise ValueError(f"{model.id}: {file} does not match its pinned SHA-256")
    return StandardEmbedder(model, folder)
