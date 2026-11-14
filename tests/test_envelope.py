"""Encrypted packages: what the corpus cannot show. The same tests as moca-reader-typescript's test/envelope.test.js."""

from __future__ import annotations

import io
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
