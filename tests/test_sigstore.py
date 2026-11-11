"""Sigstore verification is offline only, against the host's trusted root (attestations §6)."""

from __future__ import annotations

import json
import sys

import pytest
from spec_paths import MOCA_SPEC

from moca_reader import read_package

FIXTURES = MOCA_SPEC / "conformance" / "fixtures" / "sigstore"


def _codes(trust_root: dict[str, object]) -> list[str]:
    result = read_package(FIXTURES / "sigstore-signed", trust_root=trust_root)
    return [d.code for d in result.diagnostics]


def test_without_a_trusted_root_a_sigstore_bundle_is_unverifiable() -> None:
    root = json.loads((FIXTURES / "trust-root.json").read_text())
    del root["sigstore"]["trustedRoot"]
    assert _codes(root) == ["A003_ATTESTATION_UNVERIFIABLE"]


def test_an_unusable_trusted_root_is_unverifiable() -> None:
    pytest.importorskip("sigstore")
    root = json.loads((FIXTURES / "trust-root.json").read_text())
    root["sigstore"]["trustedRoot"] = {
        "certificateAuthorities": [{"certChain": {"certificates": [{"rawBytes": "AA=="}]}}]
    }
    assert _codes(root) == ["A003_ATTESTATION_UNVERIFIABLE"]


def test_without_the_extra_a_sigstore_bundle_is_unverifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in [m for m in sys.modules if m == "sigstore" or m.startswith("sigstore.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "sigstore", None)
    root = json.loads((FIXTURES / "trust-root.json").read_text())
    result = read_package(FIXTURES / "sigstore-signed", trust_root=root)
    assert [d.code for d in result.diagnostics] == ["A003_ATTESTATION_UNVERIFIABLE"]
    assert "moca-reader[sigstore]" in result.diagnostics[0].message
