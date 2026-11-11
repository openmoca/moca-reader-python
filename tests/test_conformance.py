"""moca-spec's conformance corpus, case by case, checked as moca-spec's runner checks it."""

from __future__ import annotations

import importlib.util
import json
from typing import Any

import pytest
from spec_paths import MOCA_SPEC

from moca_reader.conformance import actual_for
from moca_reader.schemas import validate_against

ROOT = MOCA_SPEC / "conformance"
CORPUS = json.loads((ROOT / "cases.json").read_text("utf-8"))
BY_ID = {c["id"]: c for c in CORPUS["cases"]}


def _same(a: list[str] | None, b: list[str] | None) -> bool:
    return sorted(set(a or [])) == sorted(set(b or []))


def _check_package(e: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    problems = []
    if e.get("valid") != actual["valid"]:
        problems.append(f"valid: expected {e.get('valid')}, got {actual['valid']}")
    if not _same(e.get("codes"), actual["codes"]):
        problems.append(f"codes: expected {sorted(set(e.get('codes') or []))}, got {sorted(set(actual['codes']))}")
    if not _same(e.get("capabilities"), actual["capabilities"]):
        problems.append(f"capabilities: expected {e.get('capabilities')}, got {actual['capabilities']}")
    if e.get("digest"):
        want = BY_ID[e["digest"][5:]]["expect"]["digest"] if e["digest"].startswith("SAME:") else e["digest"]
        if want != actual["digest"]:
            problems.append(f"digest: expected {want}, got {actual['digest']}")
    if "sidecarUsable" in e and e["sidecarUsable"] != actual.get("sidecarUsable"):
        problems.append(f"sidecarUsable: expected {e['sidecarUsable']}, got {actual.get('sidecarUsable')}")
    for path, want in (e.get("evidenceMatched") or {}).items():
        if actual["evidenceMatched"].get(path) != want:
            problems.append(f"evidenceMatched {path}: expected {want}, got {actual['evidenceMatched'].get(path)}")
    return problems


def _check_search(e: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    problems = []
    records = actual["records"]
    keys = {r["node"]["ref"] for r in records}
    if not _same(e.get("codes"), actual.get("codes")):
        problems.append(f"codes: expected {e.get('codes')}, got {actual.get('codes')}")
    problems += [f"missing {k}" for k in e.get("include") or [] if k not in keys]
    problems += [f"returned {k}, which must never be returned" for k in e.get("exclude") or [] if k in keys]
    if "count" in e and len(records) != e["count"]:
        problems.append(f"expected {e['count']} result(s), got {len(records)}")
    for k, locale in (e.get("locales") or {}).items():
        got = [r["node"].get("locale") for r in records if r["node"]["ref"] == k]
        if not got or any(g != locale for g in got):
            problems.append(f"{k}: expected locale {locale}, got {got}")
    for r in records:
        errors = validate_against("citationRecord", json.loads(json.dumps(r)))
        if errors:
            problems.append(f"{r['node']['ref']} is not a valid citation record: {errors[0]}")
        if not isinstance(r.get("score"), (int, float)):
            problems.append(f"{r['node']['ref']} has no score")
    return problems


def _check_structure(e: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    problems = []
    if not _same(e.get("codes"), actual.get("codes")):
        problems.append(f"codes: expected {e.get('codes')}, got {actual.get('codes')}")
    if json.loads(json.dumps(e["result"])) != json.loads(json.dumps(actual["result"])):
        problems.append(f"result: expected {e['result']}, got {actual['result']}")
    return problems


@pytest.mark.parametrize("case", CORPUS["cases"], ids=[c["id"] for c in CORPUS["cases"]])
def test_case(case: dict[str, Any]) -> None:
    # Reader contract §14: this Reader names Sigstore verification as an optional feature it does not implement.
    if "sigstore" in case.get("requires", []) and importlib.util.find_spec("sigstore") is None:
        pytest.skip("Sigstore verification needs the sigstore extra")
    actual = actual_for(str(ROOT), case)
    kind = case.get("kind", "package")
    check = _check_search if kind == "search" else _check_structure if kind == "structure" else _check_package
    assert check(case["expect"], actual) == []
