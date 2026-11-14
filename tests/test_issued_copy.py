"""Attestations §3a and §7.1. The corpus covers the rules; these cover what it cannot.

The same tests as moca-reader-typescript's test/issued-copy.test.js.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime

import pytest
from spec_paths import MOCA_SPEC

from moca_reader import Library, MemoryStoreBackend, Search, StoreScope, package_state, read_package
from moca_reader.attestations import SignatureResult, TrustRoot
from moca_reader.issued_copy import check_issued_copy, ed25519_key_bytes

FIX = MOCA_SPEC / "conformance" / "fixtures"
TRUST = json.loads((FIX / "trust-root-issued.json").read_text())
NOW = datetime(2026, 9, 27, tzinfo=UTC)


def test_a_trust_root_that_gives_issued_copy_without_ids_is_refused() -> None:
    doc = copy.deepcopy(TRUST)
    del next(k for k in doc["keys"] if "issued-copy" in k["roles"])["ids"]
    with pytest.raises(ValueError, match="invalid trust root"):
        TrustRoot(doc)


def test_keys_are_compared_as_ed25519_bytes_not_as_pem_text() -> None:
    pem = (MOCA_SPEC / "fixtures" / "signing-keys" / "INSECURE-issuer.pub.pem").read_text()
    assert ed25519_key_bytes(pem) == ed25519_key_bytes(pem.replace("\n", "\r\n"))
    assert ed25519_key_bytes("not a key") is None


def test_a_store_search_recomputes_issued_copy_and_issued_change_from_the_package_state() -> None:
    r = read_package(FIX / "issued" / "copy-valid", trust_root=TRUST, now=NOW)
    state = json.loads(json.dumps(package_state(r)))
    assert state["issuedCopy"]["changedFiles"] == ["content/lessons/one.md"]
    store = MemoryStoreBackend(filter_pushdown=False).ingest(Library(clock=lambda: NOW).add(r))
    records = Search(StoreScope([state], lambda: NOW), store).search("lesson", limit=10)
    one = next(x for x in records if x["node"]["path"] == "lessons/one.md")
    assert one["node"]["issuedChange"] is True
    assert r.issued_copy is not None
    assert one["package"]["issuedCopy"]["originalDigest"] == r.issued_copy["originalDigest"]
    plain = {k: v for k, v in state.items() if k != "issuedCopy"}
    again = Search(StoreScope([plain], lambda: NOW), store).search("lesson", limit=10)
    assert all("issuedChange" not in x["node"] and "issuedCopy" not in x["package"] for x in again)


def test_a_malformed_statement_is_an_error_never_an_exception() -> None:
    r = read_package(FIX / "issued" / "copy-valid", trust_root=TRUST, now=NOW)
    statement = {
        "subject": [{"name": "x", "digest": [1]}],
        "predicateType": "https://w3id.org/moca/attestation/issued-copy/v1",
        "predicate": {"original": [], "changedFiles": []},
    }
    check = check_issued_copy(statement, SignatureResult("valid"), r.manifest, r.digest or "", r.file_digests, True)
    assert check.error
