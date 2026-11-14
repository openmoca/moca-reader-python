"""moca_reader.age: decrypt-only age v1 (https://c2sp.org/age) for encrypted packages (moca-spec encrypted packages §4).

X25519 and scrypt recipients only; no plugins, no armor, no encryption. Built on ``cryptography``, already a
dependency. The core never imports this module: a host passes ``AGE_DECRYPTOR`` to ``read_package`` to enable the
optional feature ``encryption``.

Nothing here releases plaintext before the whole payload has authenticated.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import re
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VERSION_LINE = b"age-encryption.org/v1"
MAX_HEADER_BYTES = 64 * 1024
CHUNK = 64 * 1024
TAG = 16
_ZERO_NONCE = bytes(12)
_B64 = re.compile(r"[A-Za-z0-9+/]*")
_ARG = re.compile(r"[\x21-\x7e]+")
_LINE = re.compile(rb"[\x20-\x7e]*")
_WORK_FACTOR = re.compile(r"[1-9][0-9]?")
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

AgeFailureKind = Literal["header", "noKey", "noMatch", "mac", "payload", "limit"]


class AgeError(Exception):
    """Why decryption stopped. ``kind`` maps to the encrypted-package codes in the Reader:
    ``header`` (E006), ``noKey`` (E001), ``noMatch`` and ``mac`` (E002), ``payload`` (E003), ``limit`` (T003)."""

    def __init__(self, kind: AgeFailureKind, message: str) -> None:
        super().__init__(message)
        self.kind: AgeFailureKind = kind


@dataclass(frozen=True)
class Stanza:
    type: str
    args: list[str]
    body: bytes


@dataclass(frozen=True)
class Header:
    stanzas: list[Stanza]
    header_no_mac: bytes
    mac: bytes
    payload_start: int


@dataclass(frozen=True)
class AgeKey:
    """What a key provider returned: X25519 identities, a passphrase, or a 16-byte file key."""

    identities: list[str] = field(default_factory=list)
    passphrase: str | None = None
    file_key: bytes | None = None


def _decode_b64(text: str, what: str) -> bytes:
    """Canonical, unpadded standard base64: no padding, and unused bits zero."""
    if not _B64.fullmatch(text) or len(text) % 4 == 1:
        raise AgeError("header", f"{what} is not canonical unpadded base64")
    try:
        data = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except binascii.Error as err:
        raise AgeError("header", f"{what} is not base64") from err
    if base64.b64encode(data).decode().rstrip("=") != text:
        raise AgeError("header", f"{what} is not canonical base64")
    return data


def parse_header(data: bytes, max_scrypt_work_factor: int = 20) -> Header:
    """Parses an age v1 header strictly. Raises AgeError("header") on any deviation, an scrypt stanza that is not
    alone, a work factor over the limit, a malformed X25519 or scrypt stanza, a missing payload nonce, or a header
    over 64 KiB."""
    pos = 0

    def line() -> tuple[str, int]:
        nonlocal pos
        end = data.find(b"\n", pos)
        if end < 0 or end >= MAX_HEADER_BYTES:
            raise AgeError("header", "the header is not terminated" if end < 0 else "the header is over 64 KiB")
        raw = data[pos:end]
        if not _LINE.fullmatch(raw):
            raise AgeError("header", "the header has a character outside printable ASCII")
        start = pos
        pos = end + 1
        return raw.decode("ascii"), start

    if line()[0] != VERSION_LINE.decode():
        raise AgeError("header", "not an age v1 file")
    stanzas: list[Stanza] = []
    while True:
        text, start = line()
        if text.startswith("--- "):
            mac = _decode_b64(text[4:], "the header MAC")
            if len(mac) != 32:
                raise AgeError("header", "the header MAC is not 32 bytes")
            if not stanzas:
                raise AgeError("header", "the header has no recipient stanza")
            _check_stanzas(stanzas, max_scrypt_work_factor)
            # The 16-byte payload nonce counts as header for failure purposes, as the C2SP test kit does.
            if len(data) - pos < 16:
                raise AgeError("header", "the payload nonce is missing or short")
            return Header(stanzas, data[: start + 3], mac, pos)
        if not text.startswith("-> "):
            raise AgeError("header", "expected a stanza or the MAC line")
        args = text[3:].split(" ")
        if not all(_ARG.fullmatch(a) for a in args):
            raise AgeError("header", "a stanza argument is empty or has a character outside %x21-7E")
        # The body: full 64-column lines, then one shorter (possibly empty) final line.
        body = []
        while True:
            body_line = line()[0]
            if len(body_line) > 64:
                raise AgeError("header", "a stanza body line is longer than 64 columns")
            body.append(body_line)
            if len(body_line) < 64:
                break
        stanzas.append(Stanza(args[0], args[1:], _decode_b64("".join(body), "a stanza body")))


def _check_stanzas(stanzas: list[Stanza], max_scrypt_work_factor: int) -> None:
    if any(s.type == "scrypt" for s in stanzas) and len(stanzas) != 1:
        raise AgeError("header", "an scrypt stanza must be the only stanza")
    for s in stanzas:
        if s.type == "X25519":
            if len(s.args) != 1:
                raise AgeError("header", "an X25519 stanza takes one argument")
            if len(_decode_b64(s.args[0], "an X25519 share")) != 32 or len(s.body) != 32:
                raise AgeError("header", "an X25519 share or body is not 32 bytes")
        elif s.type == "scrypt":
            if len(s.args) != 2:
                raise AgeError("header", "an scrypt stanza takes two arguments")
            if len(_decode_b64(s.args[0], "an scrypt salt")) != 16:
                raise AgeError("header", "an scrypt salt is not 16 bytes")
            if not _WORK_FACTOR.fullmatch(s.args[1]):
                raise AgeError("header", "an scrypt work factor is not a decimal number")
            if int(s.args[1]) > max_scrypt_work_factor:
                raise AgeError(
                    "header", f"the scrypt work factor {s.args[1]} is over the limit of {max_scrypt_work_factor}"
                )
            if len(s.body) != 32:
                raise AgeError("header", "an scrypt stanza body is not 32 bytes")


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _open(key: bytes, nonce: bytes, sealed: bytes) -> bytes | None:
    if len(sealed) < TAG:
        return None
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, sealed, None)
    except InvalidTag:
        return None


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def decode_identity(text: str) -> bytes | None:
    """The 32-byte X25519 scalar of an ``AGE-SECRET-KEY-1…`` identity (Bech32), or None when it is not one."""
    if text not in (text.upper(), text.lower()):
        return None
    s = text.lower()
    sep = s.rfind("1")
    if s[:sep] != "age-secret-key-":
        return None
    data = [_BECH32.find(c) for c in s[sep + 1 :]]
    if len(data) < 6 or any(d < 0 for d in data):
        return None
    hrp = s[:sep]
    if _polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data) != 1:
        return None
    acc = bits = 0
    out = bytearray()
    for v in data[:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or acc & ((1 << bits) - 1) or len(out) != 32:
        return None
    return bytes(out)


def _unwrap_x25519(header: Header, identities: list[str]) -> bytes:
    keys = []
    for identity in identities:
        scalar = decode_identity(identity)
        if scalar is None:
            raise AgeError("noMatch", "an identity from the key provider is not a valid AGE-SECRET-KEY-1 identity")
        private = X25519PrivateKey.from_private_bytes(scalar)
        keys.append((private, private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))
    for s in header.stanzas:
        if s.type != "X25519":
            continue
        share = base64.b64decode(s.args[0] + "=")
        public = X25519PublicKey.from_public_bytes(share)
        for private, recipient in keys:
            try:
                shared = private.exchange(public)
            except ValueError:
                shared = bytes(32)
            # A low-order share gives the all-zero secret, which age forbids (constant-time check).
            if hmac.compare_digest(shared, bytes(32)):
                raise AgeError("header", "an X25519 share is a low-order point")
            file_key = _open(_hkdf(shared, share + recipient, b"age-encryption.org/v1/X25519"), _ZERO_NONCE, s.body)
            if file_key is not None and len(file_key) == 16:
                return file_key
    raise AgeError("noMatch", "no identity unwraps an X25519 stanza")


def _unwrap_scrypt(stanza: Stanza, passphrase: str) -> bytes:
    salt = b"age-encryption.org/v1/scrypt" + base64.b64decode(stanza.args[0] + "==")
    key = Scrypt(salt=salt, length=32, n=2 ** int(stanza.args[1]), r=8, p=1).derive(passphrase.encode("utf-8"))
    file_key = _open(key, _ZERO_NONCE, stanza.body)
    if file_key is None or len(file_key) != 16:
        raise AgeError("noMatch", "the passphrase does not unwrap the scrypt stanza")
    return file_key


def unwrap_file_key(header: Header, key: AgeKey | None) -> bytes:
    """``noKey`` when the key is missing or of a kind no stanza uses; ``noMatch`` when it is the right kind but fails."""
    if key is not None and key.file_key is not None:
        if len(key.file_key) != 16:
            raise AgeError("noMatch", "the file key from the key provider is not 16 bytes")
        return key.file_key
    if key is not None and key.identities:
        if not any(s.type == "X25519" for s in header.stanzas):
            raise AgeError("noKey", "the key provider returned identities, and the file has no X25519 stanza")
        return _unwrap_x25519(header, key.identities)
    if key is not None and key.passphrase is not None:
        stanza = next((s for s in header.stanzas if s.type == "scrypt"), None)
        if stanza is None:
            raise AgeError("noKey", "the key provider returned a passphrase, and the file has no scrypt stanza")
        return _unwrap_scrypt(stanza, key.passphrase)
    raise AgeError("noKey", "the key provider returned no key")


def verify_mac(header: Header, file_key: bytes) -> None:
    """Verifies the header MAC with a constant-time compare."""
    mac = hmac.new(_hkdf(file_key, b"", b"header"), header.header_no_mac, sha256).digest()
    if not hmac.compare_digest(mac, header.mac):
        raise AgeError("mac", "the header MAC does not verify")


def decrypt_payload(data: bytes, header: Header, file_key: bytes, max_bytes: int | None = None) -> bytes:
    """Decrypts and authenticates the whole STREAM payload; returns nothing until every chunk has authenticated."""
    key = _hkdf(file_key, data[header.payload_start : header.payload_start + 16], b"payload")
    out = bytearray()
    pos = header.payload_start + 16
    counter = 0
    while True:
        last = len(data) - pos <= CHUNK + TAG
        sealed = data[pos:] if last else data[pos : pos + CHUNK + TAG]
        plain = _open(key, counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00"), sealed)
        if plain is None:
            raise AgeError(
                "payload",
                "the final chunk does not authenticate, or is missing"
                if last
                else f"chunk {counter} does not authenticate",
            )
        if last and not plain and counter > 0:
            raise AgeError("payload", "an empty final chunk follows a full chunk")
        if max_bytes is not None and len(out) + len(plain) > max_bytes:
            raise AgeError("limit", f"the decrypted payload is over {max_bytes} bytes")
        out += plain
        if last:
            return bytes(out)
        pos += CHUNK + TAG
        counter += 1


class AgeDecryptor:
    """The decryptor a host passes to ``read_package`` to enable the optional feature ``encryption``."""

    @staticmethod
    def parse_header(data: bytes, max_scrypt_work_factor: int = 20) -> Header:
        return parse_header(data, max_scrypt_work_factor)

    @staticmethod
    def decrypt(data: bytes, header: Header, key: AgeKey | None, max_bytes: int | None = None) -> bytes:
        file_key = unwrap_file_key(header, key)
        verify_mac(header, file_key)
        return decrypt_payload(data, header, file_key, max_bytes)


AGE_DECRYPTOR = AgeDecryptor()
