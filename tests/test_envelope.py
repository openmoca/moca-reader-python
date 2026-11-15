"""Encrypted packages: what the corpus cannot show. The same tests as moca-reader-typescript's test/envelope.test.js."""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from moca_reader import bind_envelope_sidecar, read_package
from moca_reader.age import AGE_DECRYPTOR

from .spec_paths import MOCA_SPEC

ENVELOPES = MOCA_SPEC / "conformance" / "fixtures" / "envelopes"
TEST_KEY = ENVELOPES / "keys" / "INSECURE-test.txt"
OTHER_KEY = ENVELOPES / "keys" / "INSECURE-other.txt"
pytestmark = pytest.mark.skipif(not ENVELOPES.exists(), reason="moca-spec has no envelope fixtures")


def identities_in(path: Path) -> list[str]:
    return [line for line in path.read_text().splitlines() if line.startswith("AGE-SECRET-KEY-1")]


def with_key(path: Path) -> dict[str, Any]:
    ids = identities_in(path)
    return {"decryptor": AGE_DECRYPTOR, "key_provider": lambda _request: {"identities": ids}}


def test_no_decryptor_recognises_and_does_not_open() -> None:
    r = read_package(ENVELOPES / "x25519.moca.enc", key_provider=with_key(TEST_KEY)["key_provider"])
    assert not r.valid
    assert [d.code for d in r.diagnostics] == ["E001_ENCRYPTED_NO_KEY"]
    assert r.envelope is not None
    assert r.envelope["opened"] is False
    assert r.envelope["format"] == "moca-enc-v1"
    assert r.envelope["outline"] == {
        "id": "https://example.com/conformance/minimal",
        "version": "1.0.0",
        "title": "Fixture",
    }
    assert r.manifest is None
    assert r.digest is None
    assert r.nodes == []


def test_no_decryptor_entry_checks_still_run() -> None:
    r = read_package(ENVELOPES / "extra-entry.moca.enc")
    assert [d.code for d in r.diagnostics] == ["E005_ENVELOPE_INVALID"]


def test_bytes_open_like_a_path() -> None:
    a = read_package((ENVELOPES / "x25519.moca.enc").read_bytes(), **with_key(TEST_KEY))
    b = read_package(ENVELOPES / "x25519.moca.enc", **with_key(TEST_KEY))
    assert a.valid
    assert a.digest == b.digest
    assert a.envelope == {"format": "moca-enc-v1", "opened": True}


def test_throwing_key_provider_is_e001_never_raised() -> None:
    def boom(_request: dict[str, Any]) -> None:
        raise RuntimeError("vault offline")

    r = read_package(ENVELOPES / "x25519.moca.enc", decryptor=AGE_DECRYPTOR, key_provider=boom)
    assert [d.code for d in r.diagnostics] == ["E001_ENCRYPTED_NO_KEY"]


def test_key_provider_gets_stanzas_outline_and_file() -> None:
    seen: dict[str, Any] = {}

    def provider(request: dict[str, Any]) -> None:
        seen.update(request)

    read_package(ENVELOPES / "x25519.moca.enc", decryptor=AGE_DECRYPTOR, key_provider=provider)
    assert seen["file"] == "package"
    assert seen["stanzas"][0]["type"] == "X25519"
    assert len(seen["stanzas"][0]["body"]) == 32
    assert seen["outline"]["title"] == "Fixture"


def test_opens_without_writing_any_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Encrypted packages §5.4: decrypted bytes never go to a file. Python falls back from an unwritable TMPDIR to
    /tmp on its own, so this test is stricter than the other Readers': any temporary file, or any file opened for
    writing, fails the read."""
    import builtins

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("the Reader tried to create a temporary file")

    for name in (
        "mkstemp",
        "mkdtemp",
        "TemporaryFile",
        "NamedTemporaryFile",
        "SpooledTemporaryFile",
        "TemporaryDirectory",
    ):
        monkeypatch.setattr(tempfile, name, refuse)
    real_open = builtins.open

    def read_only_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if any(c in mode for c in "wax+"):
            raise AssertionError(f"the Reader tried to write {file}")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", read_only_open)
    real_os_open = os.open

    def read_only_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC):
            raise AssertionError(f"the Reader tried to write {path}")
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", read_only_os_open)
    r = read_package(ENVELOPES / "large.moca.enc", **with_key(TEST_KEY))
    assert r.valid
    assert r.envelope is not None and r.envelope["opened"] is True


@pytest.mark.skipif(shutil.which("age") is None, reason="the Go age CLI is not installed")
def test_index_age_binds_through_the_key_provider(tmp_path: Path) -> None:
    """Encrypted packages §6: index.age, encrypted at test time with the Go age CLI."""
    sidecar = io.BytesIO()
    with zipfile.ZipFile(sidecar, "w") as z:
        root = MOCA_SPEC / "conformance" / "fixtures" / "sidecars" / "valid"
        for p in sorted(root.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(root).as_posix())
    match = re.search(r"public key: (age1\w+)", TEST_KEY.read_text())
    assert match is not None
    index_age = subprocess.run(
        ["age", "-r", match[1]], input=sidecar.getvalue(), capture_output=True, check=True
    ).stdout
    path = tmp_path / "with-index.moca.enc"
    shutil.copy(ENVELOPES / "x25519.moca.enc", path)
    with zipfile.ZipFile(path, "a") as z:
        z.writestr(zipfile.ZipInfo("index.age"), index_age, compress_type=zipfile.ZIP_STORED)

    pkg = read_package(path, **with_key(TEST_KEY))
    assert pkg.valid
    bound = bind_envelope_sidecar(path, pkg, **with_key(TEST_KEY))
    assert bound.usable
    assert bound.diagnostics == []
    wrong = bind_envelope_sidecar(path, pkg, **with_key(OTHER_KEY))
    assert not wrong.usable
    assert [d.code for d in wrong.diagnostics] == ["E002_DECRYPTION_FAILED"]
    assert pkg.valid


def test_a_key_provider_error_never_reaches_a_diagnostic() -> None:
    def provider(_request: Any) -> Any:
        raise RuntimeError("vault https://vault.example/v1?token=s3cret is offline")

    r = read_package(ENVELOPES / "x25519.moca.enc", decryptor=AGE_DECRYPTOR, key_provider=provider)
    [d] = r.diagnostics
    assert d.code == "E001_ENCRYPTED_NO_KEY"
    assert "s3cret" not in d.message and "vault.example" not in d.message
    assert "RuntimeError" in d.message


class _Boom:
    def __init__(self, in_parse: bool) -> None:
        self.in_parse = in_parse

    def parse_header(self, data: bytes, max_scrypt_work_factor: int = 20) -> Any:
        if self.in_parse:
            raise IndexError("internal")
        return AGE_DECRYPTOR.parse_header(data, max_scrypt_work_factor)

    def decrypt(self, data: bytes, header: Any, key: Any, max_bytes: int | None = None) -> bytes:
        raise TypeError("internal")


def test_nothing_a_decryptor_raises_reaches_the_caller() -> None:
    key = with_key(TEST_KEY)["key_provider"]
    r = read_package(ENVELOPES / "x25519.moca.enc", decryptor=_Boom(True), key_provider=key)
    assert [d.code for d in r.diagnostics] == ["E006_AGE_HEADER_INVALID"]
    r = read_package(ENVELOPES / "x25519.moca.enc", decryptor=_Boom(False), key_provider=key)
    assert [d.code for d in r.diagnostics] == ["E002_DECRYPTION_FAILED"]
    for result, code in (
        (42, "E001_ENCRYPTED_NO_KEY"),
        ([], "E001_ENCRYPTED_NO_KEY"),
        ({"identities": [7]}, "E002_DECRYPTION_FAILED"),
        ({"fileKey": [1, 2]}, "E002_DECRYPTION_FAILED"),
    ):
        r = read_package(ENVELOPES / "x25519.moca.enc", decryptor=AGE_DECRYPTOR, key_provider=lambda _r, v=result: v)
        assert [d.code for d in r.diagnostics] == [code], result


def test_a_work_factor_limit_outside_1_to_22_is_a_host_error() -> None:
    for bad in (float("nan"), 40, 0):
        with pytest.raises(ValueError):
            read_package(ENVELOPES / "x25519.moca.enc", limits={"maxScryptWorkFactor": bad}, **with_key(TEST_KEY))  # type: ignore[dict-item]


def test_file_key_by_either_name() -> None:
    """Encrypted packages §5.1: a binding may use its own names (``file_key``) and also accepts the spec's (``fileKey``)."""
    from moca_reader.age import find_file_key

    header = AGE_DECRYPTOR.parse_header(zipfile.ZipFile(ENVELOPES / "x25519.moca.enc").read("package.age"))
    key = find_file_key(header, {"identities": identities_in(TEST_KEY)})
    for name in ("file_key", "fileKey"):
        r = read_package(
            ENVELOPES / "x25519.moca.enc", decryptor=AGE_DECRYPTOR, key_provider=lambda _r, n=name: {n: bytes(key)}
        )
        assert r.valid, name


def test_a_work_factor_limit_is_checked_when_the_read_starts() -> None:
    """Reader contract §3: an invalid limit is a host error even when no envelope is read."""
    plain = MOCA_SPEC / "examples" / "support-kb"
    with pytest.raises(ValueError):
        read_package(plain, limits={"maxScryptWorkFactor": 40})
    with pytest.raises(ValueError):
        bind_envelope_sidecar(ENVELOPES / "x25519.moca.enc", None, limits={"maxScryptWorkFactor": 0})


def test_null_identities_are_e002() -> None:
    """The same code in every Reader: a key was supplied, and it cannot be used."""
    r = read_package(
        ENVELOPES / "x25519.moca.enc", decryptor=AGE_DECRYPTOR, key_provider=lambda _r: {"identities": None}
    )
    assert [d.code for d in r.diagnostics] == ["E002_DECRYPTION_FAILED"]


def test_a_decryptor_error_with_an_unhashable_kind_is_mapped_not_raised() -> None:
    class Odd(Exception):
        def __init__(self) -> None:
            super().__init__("odd")
            self.kind: Any = ["header"]

    class OddDecryptor(_Boom):
        def parse_header(self, data: bytes, max_scrypt_work_factor: int = 20) -> Any:
            raise Odd()

    key = with_key(TEST_KEY)["key_provider"]
    r = read_package(ENVELOPES / "x25519.moca.enc", decryptor=OddDecryptor(True), key_provider=key)
    assert [d.code for d in r.diagnostics] == ["E006_AGE_HEADER_INVALID"]


def test_the_plaintext_is_read_in_place_and_zeroed(monkeypatch: pytest.MonkeyPatch) -> None:
    """F4 and F6: the decrypted archive is opened without a copy, and zeroed once its entries are read."""
    from moca_reader import source as source_module

    returned: list[bytearray] = []
    opened: list[object] = []

    class Keep(_Boom):
        def parse_header(self, data: bytes, max_scrypt_work_factor: int = 20) -> Any:
            return AGE_DECRYPTOR.parse_header(data, max_scrypt_work_factor)

        def decrypt(self, data: bytes, header: Any, key: Any, max_bytes: int | None = None) -> bytes:
            plain = AGE_DECRYPTOR.decrypt(data, header, key, max_bytes)
            assert isinstance(plain, bytearray)
            returned.append(plain)
            return plain

    real = source_module.archive_source

    def spy(archive: Any, limits: Any = None) -> Any:
        opened.append(archive)
        return real(archive, limits)

    monkeypatch.setattr(source_module, "archive_source", spy)
    r = read_package(
        ENVELOPES / "x25519.moca.enc", decryptor=Keep(False), key_provider=with_key(TEST_KEY)["key_provider"]
    )
    assert r.valid
    [plain] = returned
    assert any(o is plain for o in opened), "the plaintext was copied before it was opened"
    assert len(plain) > 0 and not any(plain)


def test_an_opened_envelope_has_no_source() -> None:
    """Its decrypted archive is zeroed after reading, so there is nothing left to read from."""
    r = read_package(ENVELOPES / "x25519.moca.enc", **with_key(TEST_KEY))
    assert r.valid and r.source is None
    unopened = read_package(ENVELOPES / "x25519.moca.enc")
    assert unopened.source is not None
