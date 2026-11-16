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


def test_a_dense_sidecar_bound_to_an_issued_copy_keeps_each_vector_with_its_item(tmp_path: object) -> None:
    """Sidecar spec §5: the changed file's items are replaced, and later vector rows stay with their own items."""
    import shutil
    import struct
    from pathlib import Path

    from moca_reader import bind_sidecar

    sidecar = Path(str(tmp_path)) / "sidecar"
    shutil.copytree(FIX / "sidecars" / "issued-original", sidecar)
    index = json.loads((sidecar / "index.json").read_text())
    index["indexType"] = "dense"
    index["model"] = {"name": "test-model", "dimensions": 2}
    index["storage"]["vectors"] = {"file": "payload/vectors.f32", "dtype": "float32", "dimensions": 2}
    (sidecar / "index.json").write_text(json.dumps(index))
    # One row per item, in payload order: intro.md, lessons/one.md (changed in the copy), lessons/two.md.
    (sidecar / "payload" / "vectors.f32").write_bytes(struct.pack("<6f", 1, 0, 0.5, 0.5, 0, 1))
    copy_result = read_package(FIX / "issued" / "copy-valid", trust_root=TRUST, now=NOW)
    bound = bind_sidecar(sidecar, copy_result)
    assert bound.usable
    assert [d.code for d in bound.diagnostics] == ["S009_SIDECAR_ITEMS_REPLACED"]
    by_path = {c["path"]: c for c in bound.chunks}
    assert list(by_path["intro.md"]["vector"]) == [1, 0]
    assert list(by_path["lessons/two.md"]["vector"]) == [0, 1]
    assert "vector" not in by_path["lessons/one.md"]
    rep = next(n for n in copy_result.nodes if n.path == "lessons/one.md").representations[0]
    assert by_path["lessons/one.md"]["start"] == rep.body_offset
    assert by_path["lessons/one.md"]["end"] == rep.body_offset + len(rep.body.encode("utf-8"))


def test_max_members_defaults_to_4096() -> None:
    """Reader contract §3: the member limit counts every depth, so a large composite package needs room."""
    from moca_reader.source import DEFAULT_LIMITS

    assert DEFAULT_LIMITS["maxMembers"] == 4096
    assert DEFAULT_LIMITS["maxMemberDepth"] == 8
