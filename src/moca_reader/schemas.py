"""Vendored copies of moca-spec's schemas/v1. tests/test_schemas.py keeps them byte-identical to the spec's."""

from __future__ import annotations

import json
import math
from collections.abc import Iterator
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
    "mocaEnc": "moca-enc",
    "terms": "terms",
    "catalogueEntry": "catalogue-entry",
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
    for err in _validator(name).iter_errors(_without_non_finite(value)):
        where = "/" + "/".join(str(p) for p in err.absolute_path) if err.absolute_path else "(root)"
        msg = f"{where} {err.message}"
        if msg not in out:
            out.append(msg)
    return out


def schema_errors(name: str, value: Any) -> Iterator[tuple[str, list[str], Any, dict[str, Any], str]]:
    """Structured errors, as Ajv reports them with ``allErrors``: ``(keyword, path, instance, schema, message)``,
    where ``schema`` is the subschema holding the keyword. A failed ``oneOf`` or ``anyOf`` gives its branches'
    errors, not its own (terms, contract §15)."""
    pending = list(_validator(name).iter_errors(_without_non_finite(value)))
    while pending:
        err = pending.pop(0)
        if err.validator in ("oneOf", "anyOf"):
            pending[0:0] = list(err.context or [])
            continue
        schema_at: Any = err.schema
        yield (
            str(err.validator),
            [str(p) for p in err.absolute_path],
            err.instance,
            schema_at if isinstance(schema_at, dict) else {},
            err.message,
        )


def _without_non_finite(v: Any) -> Any:
    """Package spec §5.1: .inf, .nan and numbers too large to be finite are neither numbers nor strings to the schemas."""
    if isinstance(v, float) and not math.isfinite(v):
        return {}
    if isinstance(v, list):
        return [_without_non_finite(x) for x in v]
    if isinstance(v, dict):
        return {k: _without_non_finite(x) for k, x in v.items()}
    return v
