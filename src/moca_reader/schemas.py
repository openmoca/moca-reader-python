"""Vendored copies of moca-spec's schemas/v1. tests/test_schemas.py keeps them byte-identical to the spec's."""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

_FILES = {
    "manifest": "manifest",
    "node": "node",
    "citationRecord": "citation-record",
    "sidecarIndex": "sidecar-index",
    "reviewPredicate": "review-predicate",
    "trustRoot": "trust-root",
    "searchHit": "search-hit",
    "structure": "structure",
}


@cache
def schema(name: str) -> dict[str, Any]:
    text = files("moca_reader").joinpath("schemas", f"{_FILES[name]}.schema.json").read_text("utf-8")
    loaded: dict[str, Any] = json.loads(text)
    return loaded


@cache
def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(schema(name), format_checker=FormatChecker(["date", "date-time"]))


def validate_against(name: str, value: Any) -> list[str]:
    """Human-readable errors; empty when valid."""
    out: list[str] = []
    for err in _validator(name).iter_errors(value):
        where = "/" + "/".join(str(p) for p in err.absolute_path) if err.absolute_path else "(root)"
        msg = f"{where} {err.message}"
        if msg not in out:
            out.append(msg)
    return out
