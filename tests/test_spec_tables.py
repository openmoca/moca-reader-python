"""This Reader's codes, schemas and tokeniser against moca-spec and the shared vectors."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from spec_paths import MOCA_SPEC

from moca_reader.backends.bm25 import tokens
from moca_reader.codes import CODES, RETIRED_CODES
from moca_reader.manifest import REGISTERED_URN_NIDS

CONTRACT = (MOCA_SPEC / "spec" / "moca-reader-contract.md").read_text("utf-8")
VECTORS = json.loads((Path(__file__).parent / "fixtures" / "token-vectors.json").read_text("utf-8"))
SCHEMAS = Path(__file__).resolve().parent.parent / "src" / "moca_reader" / "schemas"


def test_codes_and_severities_match_the_reader_contract_table() -> None:
    table = dict(re.findall(r"^\| `([A-Z]\d{3}_[A-Z0-9_]+)` \| (error|warning|info) \|", CONTRACT, re.MULTILINE))
    assert {code: severity for code, (severity, _) in CODES.items()} == table


def test_retired_codes_match_the_reader_contract() -> None:
    line = next(line for line in CONTRACT.split("\n") if line.startswith("Retired codes"))
    assert sorted(RETIRED_CODES) == sorted(re.findall(r"`([A-Z]\d{3}_[A-Z0-9_]+)`", line))


@pytest.mark.parametrize("name", sorted(p.name for p in (MOCA_SPEC / "schemas" / "v1").glob("*.schema.json")))
def test_vendored_schemas_are_byte_identical_to_moca_spec(name: str) -> None:
    assert (SCHEMAS / name).read_bytes() == (MOCA_SPEC / "schemas" / "v1" / name).read_bytes()


@pytest.mark.parametrize("vector", VECTORS, ids=[v["why"] for v in VECTORS])
def test_tokens_match_the_reference_reader(vector: dict[str, object]) -> None:
    assert tokens(str(vector["text"])) == vector["tokens"]


def test_tokens_lone_surrogate_separates_words_and_never_raises() -> None:
    assert tokens("a\ud800b") == ["a", "b"]


def test_registered_urn_namespaces_equal_the_moca_spec_snapshot() -> None:
    snapshot = json.loads((MOCA_SPEC / "data" / "urn-namespaces.json").read_text(encoding="utf-8"))
    assert sorted(REGISTERED_URN_NIDS) == snapshot["formal"]
