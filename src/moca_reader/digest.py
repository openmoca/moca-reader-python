"""The package digest, moca-digest-v2 (package spec §6).

The SHA-256 of a BagIt-style payload manifest (RFC 8493 manifest-sha256.txt): one ``<hex>  <path>`` line
per file, sorted by the UTF-8 bytes of the path. Computed, never declared: the same package as a
directory, an archive or a host source has the same digest.
"""

from __future__ import annotations

import hashlib
import re

from .diagnostics import Diagnostics
from .source import PackageSource
from .unicode import normalize, simple_lowercase

DIGEST_ALGORITHM = "moca-digest-v2"
DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}\Z")
MANIFEST = "moca.json"
ATTESTATIONS_DIR = "attestations"


def utf8(text: str) -> bytes:
    """UTF-8 as JavaScript encodes it: a lone surrogate becomes U+FFFD."""
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_attestation_path(path: str) -> bool:
    # Only entries under the attestations/ directory; a top-level file named
    # `attestations` is ordinary package content and is digested.
    return path.startswith(f"{ATTESTATIONS_DIR}/")


def package_files(source: PackageSource, diagnostics: Diagnostics) -> tuple[bool, dict[str, str]]:
    """The regular files that make up a package, NFC path -> stored path; P001-P003 when its identity is ambiguous."""
    files: dict[str, str] = {}
    folded: dict[str, str] = {}
    ok = True
    for entry in source.list():
        if entry.kind in ("symlink", "other"):
            what = "symbolic link" if entry.kind == "symlink" else "non-regular file"
            diagnostics.add(
                "P001_UNSUPPORTED_ENTRY",
                f'"{entry.path}" is a {what}; packages may contain regular files only',
                entry.path,
            )
            ok = False
            continue
        if entry.kind == "unreadable":
            diagnostics.add("P002_UNREADABLE_ENTRY", f'"{entry.path}" could not be read', entry.path)
            ok = False
            continue
        nfc = normalize("NFC", entry.path)
        key = simple_lowercase(nfc)
        if key in folded:
            diagnostics.add(
                "P003_PATH_COLLISION",
                f'"{entry.path}" collides with "{folded[key]}" after NFC normalisation or case folding',
                entry.path,
            )
            ok = False
            continue
        folded[key] = entry.path
        files[nfc] = entry.path
    return ok, files


def manifest_path(path: str) -> str:
    """A path as it appears in a BagIt manifest line: CR, LF and % percent-encoded (RFC 8493 §2.1.3)."""
    return path.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def manifest_text(file_digests: dict[str, str]) -> str:
    return "".join(
        f"{hexd}  {manifest_path(p)}\n" for p, hexd in sorted(file_digests.items(), key=lambda kv: utf8(kv[0]))
    )


def compute_digest(files: dict[str, str], read: object) -> tuple[str, dict[str, str], str]:
    """moca-digest-v2 over ``files`` (NFC path -> stored path), reading each with ``read(stored)``."""
    reader = read  # a callable taking a stored path
    file_digests: dict[str, str] = {}
    for nfc, stored in files.items():
        if is_attestation_path(nfc):
            continue
        file_digests[nfc] = sha256_hex(reader(stored))  # type: ignore[operator]
    text = manifest_text(file_digests)
    return f"sha256:{sha256_hex(utf8(text))}", file_digests, text
