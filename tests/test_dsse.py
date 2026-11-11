"""Attestations §5: DSSE keys are Ed25519. A trusted key of any other type verifies nothing."""

import base64

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from moca_reader.dsse import create_envelope, pre_auth_encode, verify_envelope

PAYLOAD_TYPE = "application/vnd.in-toto+json"
PAYLOAD = b'{"_type":"https://in-toto.io/Statement/v1"}'


def _pem(public_key: object) -> str:
    return public_key.public_bytes(  # type: ignore[attr-defined, no-any-return]
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _private_pem(private_key: object) -> str:
    return private_key.private_bytes(  # type: ignore[attr-defined, no-any-return]
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def _envelope(sig: bytes) -> dict[str, object]:
    return {
        "payload": base64.b64encode(PAYLOAD).decode(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [{"keyid": "k", "sig": base64.b64encode(sig).decode()}],
    }


def test_ed25519_envelope_verifies() -> None:
    key = Ed25519PrivateKey.generate()
    envelope = create_envelope(PAYLOAD, PAYLOAD_TYPE, _private_pem(key), "k")
    assert verify_envelope(envelope, lambda _: _pem(key.public_key())).ok


def test_ecdsa_signature_does_not_verify_even_when_trusted() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    sig = key.sign(pre_auth_encode(PAYLOAD_TYPE, PAYLOAD), ec.ECDSA(hashes.SHA256()))
    result = verify_envelope(_envelope(sig), lambda _: _pem(key.public_key()))
    assert not result.ok
    assert result.reason == "no signature verified against a trusted key"


def test_rsa_signature_does_not_verify_even_when_trusted() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = key.sign(pre_auth_encode(PAYLOAD_TYPE, PAYLOAD), padding.PKCS1v15(), hashes.SHA256())
    result = verify_envelope(_envelope(sig), lambda _: _pem(key.public_key()))
    assert not result.ok
    assert result.reason == "no signature verified against a trusted key"


def test_only_ed25519_keys_sign() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(ValueError, match="Ed25519"):
        create_envelope(PAYLOAD, PAYLOAD_TYPE, _private_pem(key), "k")


# Attestations §6 and §7 (0.6): strict base64 and trust-root rules.
def test_dsse_base64_accepts_both_alphabets_and_nothing_else() -> None:
    from moca_reader.dsse import decode_base64

    assert decode_base64("aGk=") == b"hi"
    assert decode_base64("aGk") == b"hi"
    assert decode_base64("_-8") == decode_base64("/+8=")
    for bad in ["aG k=", "a", "aGk==", "aGk=x", "!!!!"]:
        assert decode_base64(bad) is None, bad


def test_trust_root_refuses_repeated_keyid_and_missing_roles() -> None:
    from moca_reader.attestations import TrustRoot

    key = {"keyid": "k", "publicKey": "x", "roles": ["package"]}
    with pytest.raises(ValueError, match="more than once"):
        TrustRoot({"keys": [key, dict(key)]})
    with pytest.raises(ValueError, match="invalid trust root"):
        TrustRoot({"keys": [{"keyid": "k", "publicKey": "x"}]})
    assert TrustRoot({"keys": [{**key, "roles": []}]}).key("k", "package") is None
