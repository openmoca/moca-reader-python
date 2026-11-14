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

from moca_reader import age as age_module
from moca_reader.age import AGE_DECRYPTOR, MAX_STANZAS, AgeError, AgeKey, decode_identity, plaintext_length

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
    return None


def is_hybrid(v: Vector) -> bool:
    """A hybrid (ML-KEM) vector: Readers do not unwrap its stanzas, so it is run parse-only."""
    return any(i.startswith("AGE-SECRET-KEY-PQ-1") for i in v.identities)


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
    if is_hybrid(v):
        # The parser sees every hybrid vector: a valid header parses, and then no key unwraps it (E001).
        try:
            header = AGE_DECRYPTOR.parse_header(v.body, 22)
        except AgeError as err:
            assert err.kind == "header" and v.expect == "header failure"
            return
        with pytest.raises(AgeError) as no_key:
            AGE_DECRYPTOR.decrypt(v.body, header, {})
        assert no_key.value.kind == "noKey"
        return
    expect, payload = outcome(v)
    assert expect == v.expect
    # A failure releases no plaintext at all, so only success compares the payload hash.
    if v.expect == "success":
        assert payload == v.payload


def test_work_factor_limit_refuses_before_scrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    body = parse("scrypt").body
    with pytest.raises(AgeError) as err:
        AGE_DECRYPTOR.parse_header(body, 9)
    assert err.value.kind == "header"
    # A limit that is not an integer in 1-22 never disables the check.
    for bad in (float("nan"), 40, 0, 2.5, True):
        with pytest.raises(AgeError):
            AGE_DECRYPTOR.parse_header(body, bad)  # type: ignore[arg-type]
    # A spy: scrypt runs for a work factor within the limit, and never above it.
    calls: list[int] = []
    real = age_module.Scrypt

    class Spy:
        def __init__(self, **kwargs: object) -> None:
            calls.append(1)
            self.inner = real(**kwargs)  # type: ignore[arg-type]

        def derive(self, data: bytes) -> bytes:
            return bytes(32)

    monkeypatch.setattr(age_module, "Scrypt", Spy)
    header = AGE_DECRYPTOR.parse_header(body, 22)
    with pytest.raises(AgeError):
        AGE_DECRYPTOR.decrypt(body, header, {"passphrase": "x"})
    assert calls == [1]
    with pytest.raises(AgeError):
        AGE_DECRYPTOR.parse_header(body, int(header.stanzas[0].args[1]) - 1)
    assert calls == [1]


def test_decrypted_bytes_count_against_max_bytes_before_decrypting_and_exactly_equal_passes() -> None:
    v = parse("stream_two_chunks")
    header = AGE_DECRYPTOR.parse_header(v.body)
    key = AgeKey(identities=v.identities)
    with pytest.raises(AgeError) as err:
        AGE_DECRYPTOR.decrypt(v.body, header, key, 1000)
    assert err.value.kind == "limit"
    plain = AGE_DECRYPTOR.decrypt(v.body, header, key)
    assert len(AGE_DECRYPTOR.decrypt(v.body, header, key, len(plain))) == len(plain)
    with pytest.raises(AgeError):
        AGE_DECRYPTOR.decrypt(v.body, header, key, len(plain) - 1)


def test_plaintext_length_comes_from_the_ciphertext_length() -> None:
    full = 64 * 1024 + 16
    assert plaintext_length(16, 10**12) == 0
    assert plaintext_length(full, 10**12) == 64 * 1024
    assert plaintext_length(full + 17, 10**12) == 64 * 1024 + 1
    for bad in (0, 15, full + 16, full + 15):
        with pytest.raises(AgeError) as err:
            plaintext_length(bad, 10**12)
        assert err.value.kind == "payload"
    with pytest.raises(AgeError) as limit:
        plaintext_length(full, 100)
    assert limit.value.kind == "limit"


def test_key_results_wrong_kinds_no_key_bad_keys_no_match_several_kinds_all_tried() -> None:
    x = parse("x25519")
    s = parse("scrypt")
    xh = AGE_DECRYPTOR.parse_header(x.body)
    sh = AGE_DECRYPTOR.parse_header(s.body, 22)

    def kind(body: bytes, header: object, key: object) -> str:
        try:
            AGE_DECRYPTOR.decrypt(body, header, key)  # type: ignore[arg-type]
            return "ok"
        except AgeError as err:
            return err.kind

    async def provider() -> dict[str, object]:
        return {"identities": x.identities}

    assert kind(x.body, xh, {"passphrase": "p"}) == "noKey"
    assert kind(s.body, sh, {"identities": x.identities}) == "noKey"
    assert kind(x.body, xh, None) == "noKey"
    assert kind(x.body, xh, "AGE-SECRET-KEY-1") == "noKey"
    assert kind(x.body, xh, provider()) == "noKey"  # an awaitable: this binding's provider is synchronous
    assert kind(x.body, xh, {"identities": ["not an identity"]}) == "noMatch"
    assert kind(x.body, xh, {"identities": "AGE-SECRET-KEY-1"}) == "noMatch"
    assert kind(x.body, xh, {"passphrase": 42}) == "noMatch"
    assert kind(x.body, xh, {"file_key": bytes(15)}) == "noMatch"
    assert kind(x.body, xh, {"fileKey": bytes(15)}) == "noMatch"  # the spec's name is read too
    assert kind(x.body, xh, {"file_key": "sixteen bytes!!!"}) == "noMatch"
    assert kind(x.body, xh, {"file_key": bytes(16), "identities": x.identities}) == "ok"
    assert kind(x.body, xh, {"passphrase": "p", "identities": x.identities}) == "ok"


def test_the_header_holds_at_most_256_stanzas() -> None:
    def header(n: int) -> bytes:
        return b"age-encryption.org/v1\n" + b"-> moca-pad x\n\n" * n + b"--- " + b"A" * 43 + b"\n" + bytes(16)

    with pytest.raises(AgeError) as err:
        AGE_DECRYPTOR.parse_header(header(MAX_STANZAS + 1))
    assert "more than 256" in str(err.value)
    assert len(AGE_DECRYPTOR.parse_header(header(MAX_STANZAS)).stanzas) == MAX_STANZAS


@pytest.mark.skipif(not os.environ.get("MOCA_REQUIRE_GO_AGE"), reason="MOCA_REQUIRE_GO_AGE is not set")
def test_the_go_age_cli_is_installed_where_required() -> None:
    """CI installs the Go age CLI and sets MOCA_REQUIRE_GO_AGE, so the cross-check never skips there."""
    assert shutil.which("age") is not None, "MOCA_REQUIRE_GO_AGE is set, and `age` is not on the PATH"


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
        # MOCA's own limit: a header over 64 KiB is E006 here, and Go age has no such limit.
        if path.name == "header-over-64k.moca.enc":
            assert ours is None and go.returncode == 0
            compared += 1
            continue
        # The mixed-stanza fixture: Go age fails at the MAC, this module at the header. Both refuse it.
        assert (ours is not None) == (go.returncode == 0), path.name
        if ours is not None:
            assert ours == go.stdout, path.name
        compared += 1
    assert compared >= 15
