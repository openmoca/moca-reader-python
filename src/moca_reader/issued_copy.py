"""Attestations §3a and §7.1: issued copies, pass 1."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .attestations import PREDICATE_ISSUED_COPY, SignatureResult, scope_covers
from .digest import manifest_text, sha256_hex, utf8
from .profiles import PROFILE_ONTOLOGY
from .unicode import normalize

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass
class IssuedCopyCheck:
    """Why the attestation is invalid, or the publisher's digest and each changed path's original hash."""

    error: str | None = None
    original: str | None = None
    changed: dict[str, str] = field(default_factory=dict)


def ed25519_key_bytes(pem: Any) -> bytes | None:
    """The 32 raw bytes of an Ed25519 public key in PEM, or None. Package spec §4.11 compares keys as bytes."""
    if not isinstance(pem, str):
        return None
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except (ValueError, TypeError, UnicodeEncodeError):
        return None
    if not isinstance(key, Ed25519PublicKey):
        return None
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _issuer_allowed(issuers: list[Any], sig: SignatureResult) -> bool:
    signed = ed25519_key_bytes(sig.public_key)
    for entry in issuers:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("publicKey"), str) and signed is not None:
            if ed25519_key_bytes(entry["publicKey"]) == signed:
                return True
        elif (
            isinstance(entry.get("sigstore"), dict)
            and sig.sigstore is not None
            and (entry["sigstore"].get("issuer"), entry["sigstore"].get("subject")) == sig.sigstore
        ):
            return True
    return False


def _profile_files(manifest: dict[str, Any]) -> set[str]:
    """Files the profiles this Reader recognises define (package spec §9): the ontology profile's ``files``."""
    profiles = manifest.get("profiles")
    data = profiles.get(PROFILE_ONTOLOGY) if isinstance(profiles, dict) else None
    files = data.get("files") if isinstance(data, dict) else None
    out: set[str] = set()
    for f in files if isinstance(files, list) else []:
        if isinstance(f, dict) and isinstance(f.get("path"), str):
            out.add(normalize("NFC", f["path"]))
    return out


def rebuilt_digest(file_digests: dict[str, str], changed: dict[str, str]) -> str:
    """Attestations §7.1 step 5: the digest of the copy's manifest with each changed file's original hash."""
    rebuilt = {**file_digests, **changed}
    return f"sha256:{sha256_hex(utf8(manifest_text(rebuilt)))}"


def check_issued_copy(
    statement: dict[str, Any],
    sig: SignatureResult,
    manifest: dict[str, Any],
    digest: str,
    file_digests: dict[str, str],
    manifest_valid: bool,
) -> IssuedCopyCheck:
    """Attestations §7.1, pass 1, after the signature verified with role issued-copy."""
    if statement.get("predicateType") != PREDICATE_ISSUED_COPY:
        return IssuedCopyCheck("not an issued-copy attestation")
    package_id, version = manifest.get("id"), manifest.get("version")
    subjects = statement.get("subject") or []
    first = subjects[0] if subjects and isinstance(subjects[0], dict) else {}
    if len(subjects) != 1 or first.get("name") != f"{package_id}@{version}":
        return IssuedCopyCheck(f'subject "{first.get("name")}" does not name {package_id}@{version}')
    sub_digest = first.get("digest")
    if not isinstance(sub_digest, dict) or sub_digest.get("sha256") != digest.removeprefix("sha256:"):
        return IssuedCopyCheck("subject digest does not match the copy")
    predicate = statement.get("predicate")
    predicate = predicate if isinstance(predicate, dict) else {}
    original_obj = predicate.get("original")
    original = original_obj.get("sha256") if isinstance(original_obj, dict) else None
    if not isinstance(original, str) or not _HEX64.match(original):
        return IssuedCopyCheck("original.sha256 is not a SHA-256 digest")
    if f"sha256:{original}" == digest:
        return IssuedCopyCheck("original is the digest of the copy itself")
    listed = predicate.get("changedFiles")
    if not isinstance(listed, dict) or not listed:
        return IssuedCopyCheck("changedFiles is missing or empty")
    # Step 2: the role needs ids that cover the package.
    if not scope_covers(sig.ids, package_id):
        return IssuedCopyCheck(f"the issuer's trust-root entry has no ids covering {package_id}")
    # Step 3: the publisher's consent. A manifest that failed its schema allows nothing.
    consent = manifest.get("issuedCopies") if manifest_valid else None
    if not isinstance(consent, dict):
        return IssuedCopyCheck("the publisher allows no issued copies (no issuedCopies in moca.json)")
    if not _issuer_allowed(consent.get("issuers") or [], sig):
        return IssuedCopyCheck("the issuer is not in the publisher's issuedCopies.issuers")
    paths = [normalize("NFC", p) for p in consent.get("paths") or [] if isinstance(p, str)]
    defined = _profile_files(manifest)
    changed: dict[str, str] = {}
    # Step 4: each changed file.
    for path, entry in listed.items():
        h = entry.get("original") if isinstance(entry, dict) else None
        if path != normalize("NFC", path):
            return IssuedCopyCheck(f"changedFiles key {path} is not in NFC")
        if not (path.startswith("content/") or path.startswith("media/")):
            return IssuedCopyCheck(f"{path} is not under content/ or media/")
        if any(seg.startswith(".") for seg in path.split("/")):
            return IssuedCopyCheck(f"{path} is a hidden entry")
        if path in defined:
            return IssuedCopyCheck(f"{path} is a file a profile defines")
        if path not in file_digests:
            return IssuedCopyCheck(f"{path} is not a file in the copy")
        if not isinstance(h, str) or not _HEX64.match(h):
            return IssuedCopyCheck(f"{path}: original is not a SHA-256 hash")
        if file_digests[path] == h:
            return IssuedCopyCheck(f"{path} is listed but unchanged")
        if not any(path.startswith(p) if p.endswith("/") else path == p for p in paths):
            return IssuedCopyCheck(f"{path} is outside the paths the publisher allows")
        changed[path] = h
    # Step 5: rebuild the publisher's digest.
    if rebuilt_digest(file_digests, changed) != f"sha256:{original}":
        return IssuedCopyCheck("the rebuilt digest does not equal original")
    return IssuedCopyCheck(None, f"sha256:{original}", changed)
