"""Detached attestations (moca-attestations.md).

A package carries its attestations under attestations/, which the digest excludes. Each file is a DSSE
envelope (*.dsse.json) or a Sigstore bundle (*.sigstore.json) wrapping an in-toto v1 Statement with one of
two MOCA predicate types: package/v1 ("this exact package was published by this signer") and review/v1
("this reviewer checked these exact node files").

This Reader verifies DSSE envelopes, and Sigstore bundles when the ``sigstore`` extra is installed
(``moca-reader[sigstore]``): offline only, against the host's ``sigstore.trustedRoot`` (attestations §6). Without
the extra or a trusted root, a Sigstore bundle is unverifiable (A003).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ._js import get, json_loads, parse_date
from .dsse import decode_base64, verify_envelope
from .schemas import validate_against
from .unicode import normalize

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_PACKAGE = "https://w3id.org/moca/attestation/package/v1"
PREDICATE_REVIEW = "https://w3id.org/moca/attestation/review/v1"


def _hex_of(digest: str) -> str:
    return digest.removeprefix("sha256:")


def package_statement(package_id: str, version: str, digest: str) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": f"{package_id}@{version}", "digest": {"sha256": _hex_of(digest)}}],
        "predicateType": PREDICATE_PACKAGE,
        "predicate": {},
    }


class TrustRoot:
    """A host trust root (moca-attestations.md §6): whose signatures to accept, and for what."""

    def __init__(self, doc: dict[str, Any]) -> None:
        errors = validate_against("trustRoot", doc)
        if errors:
            raise ValueError(f"invalid trust root: {'; '.join(errors)}")
        self.doc = doc
        # Attestations §6: keyids are unique.
        self._keys: dict[str, dict[str, Any]] = {}
        for k in doc.get("keys", []):
            if k["keyid"] in self._keys:
                raise ValueError(f'invalid trust root: keyid "{k["keyid"]}" appears more than once')
            self._keys[k["keyid"]] = k

    @staticmethod
    def load(source: str | os.PathLike[str] | dict[str, Any] | TrustRoot) -> TrustRoot:
        if isinstance(source, TrustRoot):
            return source
        if isinstance(source, dict):
            return TrustRoot(source)
        with open(source, encoding="utf-8") as f:
            return TrustRoot(json.load(f))

    @staticmethod
    def _allows(entry: dict[str, Any], role: str) -> bool:
        # Attestations §6: `roles` is required; an empty list trusts the entry for nothing.
        roles = entry.get("roles")
        return isinstance(roles, list) and role in roles

    def key_entry(self, keyid: str) -> dict[str, Any] | None:
        """The trust-root entry for a keyid, or None."""
        return self._keys.get(keyid)

    def key(self, keyid: str, role: str, now: datetime | None = None) -> tuple[str, str] | None:
        """(public key PEM, identity), or None when the key is unknown, not trusted for the role, or expired."""
        entry = self._keys.get(keyid)
        if entry is None or not self._allows(entry, role):
            return None
        expires = parse_date(entry.get("expires"))
        # Attestations §6: a key is not trusted from the instant it expires; one whose expiry does not parse is
        # not trusted at all.
        if entry.get("expires") is not None and (expires is None or (now or datetime.now(UTC)) >= expires):
            return None
        return entry["publicKey"], entry.get("identity") or keyid

    def sigstore_identities(self, role: str) -> list[dict[str, Any]]:
        identities = get(self.doc.get("sigstore"), "identities") or []
        return [i for i in identities if self._allows(i, role)]


@dataclass
class ParsedAttestation:
    format: str
    container: Any
    statement: dict[str, Any]


def parse_attestation(path: str, data: bytes) -> ParsedAttestation | str:
    """The envelope and statement of an attestation file, or the reason it is malformed."""
    fmt = "sigstore" if path.endswith(".sigstore.json") else "dsse" if path.endswith(".dsse.json") else None
    if fmt is None:
        return "attestation files must end in .dsse.json or .sigstore.json"
    try:
        container = json_loads(data.decode("utf-8", errors="replace"))
    except ValueError:
        return "not valid JSON"
    envelope = container if fmt == "dsse" else get(container, "dsseEnvelope")
    if not isinstance(get(envelope, "payload"), str) or not isinstance(get(envelope, "payloadType"), str):
        return "not a DSSE envelope" if fmt == "dsse" else "Sigstore bundle has no dsseEnvelope"
    if envelope["payloadType"] != PAYLOAD_TYPE:
        return f"unexpected payloadType {envelope['payloadType']}"
    payload = decode_base64(envelope["payload"])
    if payload is None:
        return "payload is not base64 or base64url"
    try:
        statement = json_loads(payload.decode("utf-8", errors="replace"), unique_keys=True)
    except ValueError:
        return "payload is not a JSON in-toto statement"
    if (
        get(statement, "_type") != STATEMENT_TYPE
        or not isinstance(statement.get("subject"), list)
        or not isinstance(statement.get("predicateType"), str)
    ):
        return "payload is not an in-toto v1 Statement"
    return ParsedAttestation(fmt, container, statement)


@dataclass
class SignatureResult:
    outcome: str  # valid | invalid | unverifiable | indeterminate
    signer: str | None = None
    reason: str | None = None
    ids: list[str] = field(default_factory=list)
    reviewers: list[str] | None = None


def verify_signature(
    parsed: ParsedAttestation, trust_root: TrustRoot | None, role: str, now: datetime | None = None
) -> SignatureResult:
    """Verifies the signature against the host trust root; not what the statement says."""
    if trust_root is None:
        return SignatureResult("unverifiable", reason="no trust root was supplied")
    if parsed.format == "dsse":
        signer: list[str] = []

        def resolve(keyid: str) -> str | None:
            found = trust_root.key(keyid, role, now)
            if found:
                signer.append(found[1])
            return found[0] if found else None

        result = verify_envelope(parsed.container, resolve)
        if not result.ok:
            return SignatureResult("invalid", reason=result.reason)
        found = trust_root.key(result.keyid or "", role, now)
        entry = trust_root.key_entry(result.keyid or "")
        ids = [i for i in (entry or {}).get("ids", []) if isinstance(i, str)]
        listed = (entry or {}).get("reviewers")
        reviewers = [r for r in listed if isinstance(r, str)] if isinstance(listed, list) else None
        return SignatureResult(
            "valid",
            signer=found[1] if found else (signer[-1] if signer else result.keyid),
            ids=ids,
            reviewers=reviewers,
        )
    return _verify_sigstore(parsed, trust_root, role)


def _verify_sigstore(parsed: ParsedAttestation, trust_root: TrustRoot, role: str) -> SignatureResult:
    # Attestations §7, step 6: unverifiable only when the trust root lists no Sigstore identities at all, or there
    # is no trust material; identities that exist but are not trusted for this role make it invalid.
    sigstore_doc = trust_root.doc.get("sigstore")
    if not (get(sigstore_doc, "identities") or []):
        return SignatureResult("unverifiable", reason="the trust root lists no Sigstore identities")
    trusted_root = get(sigstore_doc, "trustedRoot")
    if not isinstance(trusted_root, dict):
        return SignatureResult(
            "unverifiable",
            reason="no sigstore.trustedRoot: this Reader verifies Sigstore offline, against the host's trusted root",
        )
    try:
        from sigstore.errors import Error as SigstoreError
        from sigstore.models import Bundle
        from sigstore.models import TrustedRoot as SigstoreTrustedRoot
        from sigstore.verify import Verifier, policy
        from sigstore_models.trustroot import v1 as trustroot_v1
    except ImportError:
        return SignatureResult(
            "unverifiable", reason="Sigstore verification needs the sigstore extra: pip install moca-reader[sigstore]"
        )
    identities = trust_root.sigstore_identities(role)
    if not identities:
        return SignatureResult(
            "invalid", reason=f"no Sigstore identity in the trust root is trusted for the {role} role"
        )
    try:
        verifier = Verifier(
            trusted_root=SigstoreTrustedRoot(trustroot_v1.TrustedRoot.from_json(json.dumps(trusted_root).encode()))
        )
    except Exception as err:  # any failure here: the trust material is unusable
        return SignatureResult("unverifiable", reason=f"sigstore.trustedRoot cannot be used: {err}")
    try:
        bundle = Bundle.from_json(json.dumps(parsed.container))
    except Exception as err:  # a bundle the library cannot read signs nothing
        return SignatureResult("invalid", reason=f"not a valid Sigstore bundle: {err}")
    last = "verification failed"
    for identity in identities:
        issuer, subject = identity.get("issuer"), identity.get("subject")
        if not isinstance(issuer, str) or not isinstance(subject, str):
            continue
        try:
            # Attestations §6: issuer and subject alternative name match exactly; no patterns.
            verifier.verify_dsse(bundle, policy.Identity(identity=subject, issuer=issuer))
        except (SigstoreError, ValueError) as err:
            last = str(err)
            continue
        ids = [i for i in identity.get("ids", []) if isinstance(i, str)]
        listed = identity.get("reviewers")
        reviewers = [r for r in listed if isinstance(r, str)] if isinstance(listed, list) else None
        return SignatureResult("valid", signer=f"{issuer} {subject}", ids=ids, reviewers=reviewers)
    return SignatureResult("invalid", reason=last)


def check_package_statement(statement: dict[str, Any], package_id: Any, version: Any, digest: str) -> str | None:
    """The reason the statement does not attest this package, or None."""
    if statement.get("predicateType") != PREDICATE_PACKAGE:
        return "not a package attestation"
    subjects = statement["subject"]
    subject = subjects[0] if subjects else None
    name = get(subject, "name")
    if len(subjects) != 1 or name != f"{package_id}@{version}":
        return f'subject "{name}" does not name {package_id}@{version}'
    if get(get(subject, "digest"), "sha256") != _hex_of(digest):
        return "subject digest does not match the package digest"
    return None


@dataclass
class ReviewCheck:
    error: str | None = None
    current: list[str] = field(default_factory=list)
    outdated: list[str] = field(default_factory=list)
    predicate: dict[str, Any] | None = None


def check_review_statement(statement: dict[str, Any], package_id: Any, file_digests: dict[str, str]) -> ReviewCheck:
    predicate: Any = statement.get("predicate")
    errors = validate_against("reviewPredicate", predicate)
    if errors:
        return ReviewCheck(f"review predicate is invalid: {'; '.join(errors)}")
    if predicate["package"] != package_id:
        return ReviewCheck(f"review names package {predicate['package']}, not {package_id}")
    check = ReviewCheck(predicate=predicate)
    for s in statement["subject"]:
        name, sha = get(s, "name"), get(get(s, "digest"), "sha256")
        if not isinstance(name, str) or not isinstance(sha, str):
            return ReviewCheck("review subject entries need a name and a sha256 digest")
        (check.current if file_digests.get(normalize("NFC", name)) == sha else check.outdated).append(name)
    return check


def scope_covers(scopes: list[str], package_id: Any) -> bool:
    """Package spec §7.2: whether a signer's ``ids`` cover a package id (exact, or a prefix ending in /, : or #)."""
    if not isinstance(package_id, str):
        return False
    return any(s == package_id or (s[-1:] in ("/", ":", "#") and package_id.startswith(s)) for s in scopes)
