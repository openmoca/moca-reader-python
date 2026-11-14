"""The C2SP age test kit (CCTV) against moca_reader.age, and moca-spec's envelope fixtures against the Go age CLI.

The same vectors and skips as moca-reader-typescript's test/age.test.js.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from moca_reader.age import AGE_DECRYPTOR, AgeError, AgeKey, decode_identity

from .spec_paths import MOCA_SPEC

KIT = Path(__file__).parent / "fixtures" / "cctv-age"


@dataclass
class Vector:
    expect: str = ""
    payload: str = ""
    identities: list[str] = field(default_factory=list)
    passphrases: list[str] = field(default_factory=list)
    armored: bool = False
    body: bytes = b""


def parse(name: str) -> Vector:
    raw = (KIT / name).read_bytes()
    split = raw.index(b"\n\n")
    v = Vector()
    compressed = False
    for line in raw[:split].decode().split("\n"):
        k, _, value = line.partition(": ")
        if k == "expect":
            v.expect = value
        elif k == "payload":
            v.payload = value
        elif k == "identity":
            v.identities.append(value)
        elif k == "passphrase":
            v.passphrases.append(value)
        elif k == "armored":
            v.armored = value == "yes"
        elif k == "compressed":
            compressed = value == "zlib"
    body = raw[split + 2 :]
    v.body = zlib.decompress(body) if compressed else body
    return v


def skip_reason(v: Vector) -> str | None:
    """Why a vector is not run. Each reason is recorded in the 0.7.0 notes."""
    if v.armored:
        return "ASCII armor: envelopes carry binary age only (encrypted packages §4)"
    if any(i.startswith("AGE-SECRET-KEY-PQ-1") for i in v.identities):
        return "hybrid (ML-KEM) identity: Readers unwrap X25519 and scrypt only"
    return None


def outcome(v: Vector) -> tuple[str, str | None]:
    try:
        # The kit uses the age reference limit for the work factor (22); MOCA's default is 20.
        header = AGE_DECRYPTOR.parse_header(v.body, 22)
    except AgeError as err:
        assert err.kind == "header"
        return "header failure", None
    keys = [AgeKey(identities=v.identities)] if v.identities else [AgeKey(passphrase=p) for p in v.passphrases]
    last: AgeError | None = None
    for key in keys or [None]:
        try:
            plain = AGE_DECRYPTOR.decrypt(v.body, header, key)
            return "success", hashlib.sha256(plain).hexdigest()
        except AgeError as err:
            last = err
            if err.kind not in ("noKey", "noMatch"):
                break
    assert last is not None
    names = {"header": "header failure", "noKey": "no match", "noMatch": "no match", "mac": "HMAC failure"}
    return names.get(last.kind, "payload failure"), None


VECTORS = sorted(p.name for p in KIT.iterdir() if p.name != "README.md")


def test_kit_has_every_vector() -> None:
    assert len(VECTORS) == 147


@pytest.mark.parametrize("name", VECTORS)
def test_cctv(name: str) -> None:
    v = parse(name)
    reason = skip_reason(v)
    if reason:
        pytest.skip(reason)
    expect, payload = outcome(v)
    assert expect == v.expect
    # A failure releases no plaintext at all, so only success compares the payload hash.
    if v.expect == "success":
        assert payload == v.payload


def test_work_factor_limit_refuses_before_scrypt() -> None:
    with pytest.raises(AgeError) as err:
        AGE_DECRYPTOR.parse_header(parse("scrypt").body, 9)
    assert err.value.kind == "header"


def test_decrypted_bytes_count_against_max_bytes() -> None:
    v = parse("stream_two_chunks")
    header = AGE_DECRYPTOR.parse_header(v.body)
    with pytest.raises(AgeError) as err:
        AGE_DECRYPTOR.decrypt(v.body, header, AgeKey(identities=v.identities), 1000)
    assert err.value.kind == "limit"


def test_identities_are_bech32_checked() -> None:
    good = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0"
    assert len(decode_identity(good) or b"") == 32
    assert decode_identity(good[:-1] + "Q") is None
    assert len(decode_identity(good.lower()) or b"") == 32
    assert decode_identity("AGE-secret-KEY-1" + good[16:]) is None


ENVELOPES = MOCA_SPEC / "conformance" / "fixtures" / "envelopes"


@pytest.mark.skipif(not ENVELOPES.exists(), reason="moca-spec has no envelope fixtures")
@pytest.mark.skipif(shutil.which("age") is None, reason="the Go age CLI is not installed")
def test_envelope_fixtures_match_go_age() -> None:
    """Every moca-spec envelope fixture decrypts to the same bytes here and with the Go age CLI."""
    identity_file = ENVELOPES / "keys" / "INSECURE-test.txt"
    identities = [line for line in identity_file.read_text().splitlines() if line.startswith("AGE-SECRET-KEY-1")]
    passphrase = "moca-conformance-INSECURE-passphrase"
    compared = 0
    for path in sorted(ENVELOPES.glob("*.moca.enc")):
        with zipfile.ZipFile(path) as z:
            if "package.age" not in z.namelist():
                continue
            data = z.read("package.age")
        uses_scrypt = b"-> scrypt" in data[:200]
        if uses_scrypt:
            env = {**os.environ, "AGE_PASSPHRASE": passphrase, "AGE_PASSPHRASE_MAX_WORK_FACTOR": "22"}
            go = subprocess.run(["age", "--decrypt", "-j", "batchpass"], input=data, capture_output=True, env=env)
        else:
            go = subprocess.run(["age", "--decrypt", "-i", str(identity_file)], input=data, capture_output=True)
        ours: bytes | None
        try:
            header = AGE_DECRYPTOR.parse_header(data, 22)
            key = AgeKey(passphrase=passphrase) if uses_scrypt else AgeKey(identities=identities)
            ours = AGE_DECRYPTOR.decrypt(data, header, key)
        except AgeError:
            ours = None
        # The mixed-stanza fixture: Go age fails at the MAC, this module at the header. Both refuse it.
        assert (ours is not None) == (go.returncode == 0), path.name
        if ours is not None:
            assert ours == go.stdout, path.name
        compared += 1
    assert compared >= 15
