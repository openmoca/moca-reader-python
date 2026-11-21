"""Encrypted packages (moca-spec spec/moca-encrypted-package.md): recognising and opening envelopes.

The age decryption itself is not here: a host passes a decryptor (``AGE_DECRYPTOR`` from ``moca_reader.age``) with
its key provider. Without one, this Reader does not implement the optional feature ``encryption``, and an envelope
is reported with E001 after its entries are checked. Maps one-to-one onto the reference Reader's lib/envelope.js.
"""

from __future__ import annotations

import copy
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from ._js import json_loads
from .diagnostics import Diagnostics
from .manifest import image_problem
from .schemas import validate_against
from .source import DEFAULT_LIMITS, PackageSource

MARKER = "moca-enc.json"
PACKAGE_AGE = "package.age"
INDEX_AGE = "index.age"
STRUCTURE_COPY = "outline/structure.ttl"
_ALLOWED = {MARKER, PACKAGE_AGE, STRUCTURE_COPY, INDEX_AGE}
# Encrypted packages §3: the opt-in cover copy, by name, and the type its extension gives.
COVER_COPIES = {"outline/cover.png": "image/png", "outline/cover.jpg": "image/jpeg", "outline/cover.webp": "image/webp"}
_STORED = 0

KeyProvider = Callable[[dict[str, Any]], Mapping[str, Any] | None]
"""Encrypted packages §5.1. Given ``{"stanzas", "outline", "file"}``, returns a mapping with one or more of
``"identities"`` (a list of strings), ``"passphrase"`` and ``"file_key"`` (16 bytes; the spec's ``"fileKey"`` is
accepted too), or None. It is synchronous, as ``read_package`` is: an awaitable result is refused (E001)."""


class Decryptor(Protocol):
    def parse_header(self, data: bytes, max_scrypt_work_factor: int = 20) -> Any: ...

    def decrypt(self, data: bytes, header: Any, key: Any, max_bytes: int | None = None) -> bytes | bytearray: ...


@dataclass(frozen=True)
class EnvelopeCheck:
    """What the inner archive is checked against right after its manifest is read (step 8)."""

    outline: dict[str, Any] | None
    structure: bytes | None
    cover: tuple[str, bytes] | None = None


_AGE_CODES = {
    "header": "E006_AGE_HEADER_INVALID",
    "noKey": "E001_ENCRYPTED_NO_KEY",
    "noMatch": "E002_DECRYPTION_FAILED",
    "mac": "E002_DECRYPTION_FAILED",
    "payload": "E003_PAYLOAD_CORRUPT",
    "limit": "T003_ARCHIVE_REJECTED",
}


def is_envelope(source: PackageSource, files: Mapping[str, str]) -> bool:
    """An archive with moca-enc.json at its root (encrypted packages §2)."""
    return source.kind == "archive" and MARKER in files


def _parse_marker(data: bytes) -> tuple[dict[str, Any] | None, str | None]:
    """Parses moca-enc.json like moca.json: strict UTF-8, no repeated member names, then its schema."""
    try:
        marker = json_loads(data.decode("utf-8").removeprefix("﻿"), unique_keys=True)
    except (ValueError, KeyError) as err:
        return None, f"not valid UTF-8 JSON: {err}"
    errors = validate_against("mocaEnc", marker)
    return (None, "; ".join(errors)) if errors else (marker, None)


def json_equal(a: Any, b: Any) -> bool:
    """JSON values equal as values (encrypted packages §3): objects by members, arrays in order; true is not 1."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return False
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


def outline_mismatch(
    check: EnvelopeCheck,
    manifest: Any,
    data: Mapping[str, bytes],
    max_image_bytes: int = DEFAULT_LIMITS["maxImageBytes"],
) -> str | None:
    """The outline check (encrypted packages §3); None when it passes."""
    for key, value in (check.outline or {}).items():
        if not isinstance(manifest, dict) or key not in manifest:
            return f'the outline has "{key}", and the manifest does not'
        if not json_equal(value, manifest[key]):
            return f"the outline's \"{key}\" differs from the manifest's"
    if check.structure is not None:
        inner = data.get("structure.ttl")
        if inner is None:
            return "the envelope has a structure copy, and the package has no structure.ttl"
        if inner != check.structure:
            return "the structure copy differs from structure.ttl"
    if check.cover is not None:
        name, copy_bytes = check.cover
        # The first images entry with role cover, which must pass its checks (package spec §4.6).
        images = manifest.get("images") if isinstance(manifest, dict) else None
        cover = (
            next((i for i in images if isinstance(i, dict) and i.get("role") == "cover"), None)
            if isinstance(images, list)
            else None
        )
        if cover is None or not isinstance(cover.get("src"), str) or not isinstance(cover.get("type"), str):
            return "the envelope has a cover copy, and the manifest has no cover image"
        problem = image_problem(cover["src"], cover["type"], data, max_image_bytes)
        if problem:
            return f"the envelope has a cover copy, and the manifest's cover fails its checks: {problem}"
        if COVER_COPIES[name] != cover["type"]:
            return f"the cover copy {name} does not match the cover's type {cover['type']}"
        if data[unicodedata.normalize("NFC", cover["src"])] != copy_bytes:
            return f"the cover copy differs from {cover['src']}"
    return None


def check_work_factor_limit(limits: Mapping[str, Any]) -> None:
    """Reader contract §3: ``maxScryptWorkFactor`` is an integer from 1 to 22; anything else is a host error
    (ValueError). Checked when a read starts, and again before each encrypted entry."""
    wf = {**DEFAULT_LIMITS, **limits}["maxScryptWorkFactor"]
    if not isinstance(wf, int) or isinstance(wf, bool) or not 1 <= wf <= 22:
        raise ValueError(f"limits['maxScryptWorkFactor'] must be an integer from 1 to 22, not {wf!r}")


def wipe_plaintext(plain: object) -> None:
    """Zeroes decrypted bytes once they have been read (F6). Immutable bytes cannot be zeroed."""
    if isinstance(plain, bytearray):
        plain[:] = bytes(len(plain))


def open_age_entry(
    data: bytes,
    file: str,
    outline: dict[str, Any] | None,
    decryptor: Decryptor | None,
    key_provider: KeyProvider | None,
    limits: Mapping[str, int],
) -> tuple[bytes | bytearray | None, str | None, str | None]:
    """Steps 3-6 of encrypted packages §5.2 for one encrypted entry: (plaintext, code, message)."""
    lim = {**DEFAULT_LIMITS, **limits}
    check_work_factor_limit(lim)
    if decryptor is None:
        return None, "E001_ENCRYPTED_NO_KEY", "this Reader was not given a decryptor, so it does not open envelopes"
    try:
        header = decryptor.parse_header(data, lim["maxScryptWorkFactor"])
    except Exception as err:
        return _failure(err, file, "E006_AGE_HEADER_INVALID")
    if key_provider is None:
        return None, "E001_ENCRYPTED_NO_KEY", "the host supplied no key provider"
    request = {
        "stanzas": [{"type": s.type, "args": list(s.args), "body": bytes(s.body)} for s in header.stanzas],
        "outline": copy.deepcopy(outline),
        "file": file,
    }
    try:
        # Encrypted packages §5.1: stanzas are data; the outline is unverified.
        key = key_provider(request)
    except Exception as err:
        # Encrypted packages §5.1: never the provider's own message, which may carry a token or an address.
        return None, "E001_ENCRYPTED_NO_KEY", f"the key provider failed ({type(err).__name__})"
    if key is None:
        return None, "E001_ENCRYPTED_NO_KEY", "the key provider returned no key"
    try:
        return decryptor.decrypt(data, header, key, lim["maxBytes"]), None, None
    except Exception as err:
        return _failure(err, file, "E002_DECRYPTION_FAILED")


def _failure(err: Exception, file: str, fallback: str) -> tuple[None, str, str]:
    """Encrypted packages §5.1: nothing from opening an envelope is raised to the caller. A decryptor's own failure
    maps to its code; anything else to the step's code, with its type name only. (Cancellation, KeyboardInterrupt
    and other BaseExceptions are not caught.)"""
    kind = getattr(err, "kind", None)
    # A custom decryptor's kind may be any object, even an unhashable one: only a string is looked up.
    code = _AGE_CODES.get(kind) if isinstance(kind, str) else None
    if code is not None:
        return None, code, f"{file}.age: {err}"
    return None, fallback, f"{file}.age: the decryptor failed ({type(err).__name__})"


def read_envelope(
    source: PackageSource,
    files: Mapping[str, str],
    entries_ok: bool,
    diagnostics: Diagnostics,
    result: Any,
    decryptor: Decryptor | None,
    key_provider: KeyProvider | None,
    limits: Mapping[str, int],
    read_inner: Callable[[bytes | bytearray, EnvelopeCheck], Any],
    finish: Callable[[Any, Diagnostics], Any],
) -> Any:
    """Opens an envelope in the order of encrypted packages §5.2."""
    # Step 1: the outer archive's rules (T003, P001-P003) were applied when it was opened and listed.
    if not entries_ok:
        return finish(result, diagnostics)
    result.envelope = {"opened": False}

    def fail(code: str, message: str, file: str | None = None) -> Any:
        diagnostics.add(code, message, file)
        return finish(result, diagnostics)

    # Step 2: the entry set and the marker.
    if "moca.json" in files:
        return fail(
            "E005_ENVELOPE_INVALID",
            "a Zip with both moca.json and moca-enc.json at its root is neither a package nor an envelope",
            MARKER,
        )
    if source.hidden_entries:
        return fail("E005_ENVELOPE_INVALID", f'an envelope may not have a hidden entry: "{source.hidden_entries[0]}"')
    for path in files:
        if path not in _ALLOWED and path not in COVER_COPIES:
            return fail("E005_ENVELOPE_INVALID", f'an envelope may not have the entry "{path}"', path)
    if PACKAGE_AGE not in files:
        return fail("E005_ENVELOPE_INVALID", "the envelope has no package.age")
    covers = [name for name in COVER_COPIES if name in files]
    if len(covers) > 1:
        return fail(
            "E005_ENVELOPE_INVALID",
            f"an envelope has at most one cover copy, and this one has {', '.join(covers)}",
            covers[1],
        )
    methods = {e.path: e.method for e in source.list()}
    for name in (PACKAGE_AGE, INDEX_AGE):
        if name in files and methods.get(files[name]) != _STORED:
            return fail("E005_ENVELOPE_INVALID", f"{name} must be stored, not compressed", name)
    try:
        marker, error = _parse_marker(source.read(files[MARKER]))
    except (OSError, KeyError) as err:
        return fail("P002_UNREADABLE_ENTRY", f'"{MARKER}" could not be read: {err}', MARKER)
    if marker is None:
        return fail("E005_ENVELOPE_INVALID", f"moca-enc.json is invalid: {error}", MARKER)
    fmt = marker["format"]
    outline = marker.get("outline")
    result.envelope = {"format": fmt, "opened": False, **({"outline": copy.deepcopy(outline)} if outline else {})}

    # Steps 3-6.
    try:
        package_bytes = source.read(files[PACKAGE_AGE])
        structure = source.read(files[STRUCTURE_COPY]) if STRUCTURE_COPY in files else None
        cover = (covers[0], source.read(files[covers[0]])) if covers else None
    except (OSError, KeyError) as err:
        return fail("P002_UNREADABLE_ENTRY", f"an envelope entry could not be read: {err}")
    max_image_bytes = {**DEFAULT_LIMITS, **limits}["maxImageBytes"]
    if cover is not None and len(cover[1]) > max_image_bytes:
        return fail(
            "E005_ENVELOPE_INVALID",
            f"{cover[0]} is {len(cover[1])} bytes, over the limit of {max_image_bytes}",
            cover[0],
        )
    plain, code, message = open_age_entry(package_bytes, "package", outline, decryptor, key_provider, limits)
    if plain is None:
        assert code is not None and message is not None
        return fail(code, message, PACKAGE_AGE)

    # Steps 7-10, with the outline check (step 8) right after the inner manifest is read.
    try:
        inner = read_inner(plain, EnvelopeCheck(outline, structure, cover))
    finally:
        # Every inner entry has been copied out by now: the decrypted archive itself is not kept.
        wipe_plaintext(plain)
    failed = inner.manifest is None or any(
        d.severity == "error" and (d.code[0] in "TP" or d.code == "E004_OUTLINE_MISMATCH") for d in inner.diagnostics
    )
    if failed:
        # Encrypted packages §5.3: nothing from the inner archive is exposed; its diagnostics are reported.
        diagnostics.items.extend(inner.diagnostics)
        return finish(result, diagnostics)
    inner.envelope = {"format": fmt, "opened": True}
    # The decrypted archive has been zeroed, so an opened envelope has no source to read from.
    inner.source = None
    return inner


def bind_envelope_sidecar(
    target: Any,
    pkg: Any,
    *,
    decryptor: Decryptor | None = None,
    key_provider: KeyProvider | None = None,
    limits: Mapping[str, int] | None = None,
    strict: bool = False,
) -> Any:
    """Binds an envelope's ``index.age`` to the result of reading that envelope (encrypted packages §6).

    Opened through the same key provider (``file: "index"``) and steps 3-6, then bound as any sidecar. A failure makes
    the sidecar unusable and is reported here with its code; it never changes the package's validity.
    """
    from .sidecar import SidecarBinding, bind_sidecar
    from .source import TargetError, open_source

    check_work_factor_limit(limits or {})
    diagnostics = Diagnostics(strict)
    out = SidecarBinding(diagnostics=diagnostics.items)
    envelope = getattr(pkg, "envelope", None) or {}
    if not envelope.get("opened"):
        diagnostics.add("S001_SIDECAR_INVALID", "index.age binds only to an opened envelope")
        return out
    try:
        source = open_source(target, dict(limits or {}))
        entry = next((e for e in source.list() if e.path == INDEX_AGE), None)
    except TargetError as err:
        diagnostics.add("S001_SIDECAR_INVALID", str(err))
        return out
    if entry is None:
        diagnostics.add("S001_SIDECAR_INVALID", "the envelope has no index.age")
        return out
    if entry.method != _STORED:
        diagnostics.add("E005_ENVELOPE_INVALID", "index.age must be stored, not compressed", INDEX_AGE)
        return out
    try:
        index_bytes = source.read(INDEX_AGE)
    except (OSError, KeyError) as err:
        diagnostics.add("S001_SIDECAR_INVALID", f'"{INDEX_AGE}" could not be read: {err}', INDEX_AGE)
        return out
    plain, code, message = open_age_entry(
        index_bytes, "index", envelope.get("outline"), decryptor, key_provider, limits or {}
    )
    if plain is None:
        assert code is not None and message is not None
        diagnostics.add(code, message, INDEX_AGE)
        return out
    try:
        bound = bind_sidecar(plain, pkg, strict)
    finally:
        wipe_plaintext(plain)
    diagnostics.items.extend(bound.diagnostics)
    bound.diagnostics = diagnostics.items
    return bound
