"""DSSE (Dead Simple Signing Envelope): https://github.com/secure-systems-lab/dsse, with Ed25519 keys."""

from __future__ import annotations

import base64
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .ed25519 import strict_encodings

PAE_PREFIX = "DSSEv1"


def pre_auth_encode(payload_type: str, payload: bytes) -> bytes:
    """Pre-Authentication Encoding: ``DSSEv1 <len> <type> <len> <body>``, lengths in bytes."""
    type_bytes = payload_type.encode("utf-8")
    return b"".join([f"{PAE_PREFIX} {len(type_bytes)} ".encode(), type_bytes, f" {len(payload)} ".encode(), payload])


def create_envelope(payload: bytes, payload_type: str, private_key_pem: str, keyid: str) -> dict[str, Any]:
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("DSSE envelopes are signed with Ed25519 keys")
    signature = key.sign(pre_auth_encode(payload_type, payload))
    return {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": payload_type,
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(signature).decode()}],
    }


@dataclass
class EnvelopeResult:
    ok: bool
    reason: str | None = None
    payload: bytes | None = None
    keyid: str | None = None


_BASE64 = re.compile(r"^[A-Za-z0-9+/_-]*={0,2}\Z")


def decode_base64(text: Any) -> bytes | None:
    """Attestations §7: base64 (RFC 4648 §4) or base64url (§5), with or without padding; anything else is None."""
    if not isinstance(text, str) or not _BASE64.match(text):
        return None
    body = text.rstrip("=")
    if len(body) % 4 == 1 or (len(text) != len(body) and len(text) % 4 != 0):
        return None
    return base64.b64decode(body.replace("-", "+").replace("_", "/") + "=" * (-len(body) % 4))


def verify_envelope(envelope: Any, resolve_public_key: Callable[[str], str | None]) -> EnvelopeResult:
    if (
        not isinstance(envelope, dict)
        or not isinstance(envelope.get("payload"), str)
        or not isinstance(envelope.get("payloadType"), str)
        or not isinstance(envelope.get("signatures"), list)
        or len(envelope["signatures"]) == 0
    ):
        return EnvelopeResult(False, "malformed DSSE envelope")
    payload = decode_base64(envelope["payload"])
    if payload is None:
        return EnvelopeResult(False, "envelope payload is not valid base64")
    pae = pre_auth_encode(envelope["payloadType"], payload)
    for entry in envelope["signatures"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("keyid"), str)
            or not isinstance(entry.get("sig"), str)
        ):
            continue
        signature = decode_base64(entry["sig"])
        if signature is None:
            continue
        public_key_pem = resolve_public_key(entry["keyid"])
        if not public_key_pem:
            continue
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode())
            if not isinstance(key, Ed25519PublicKey):
                continue
            # Attestations §5: strict encodings first, so every Reader's library reaches the same answer.
            raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if not strict_encodings(raw, signature):
                continue
            key.verify(signature, pae)
        except (InvalidSignature, ValueError, TypeError):
            continue
        return EnvelopeResult(True, payload=payload, keyid=entry["keyid"])
    return EnvelopeResult(False, "no signature verified against a trusted key")
