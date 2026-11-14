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
import inspect
import re
from collections.abc import Mapping
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
MAX_STANZAS = 256
"""Reader contract §3: the header holds at most this many stanzas (E006)."""
SCRYPT_WORK_FACTOR_RANGE = (1, 22)
"""Reader contract §3: ``maxScryptWorkFactor`` is an integer in this range."""
DEFAULT_MAX_BYTES = 512 * 1024 * 1024
"""The Reader's default ``maxBytes`` (Reader contract §3), used when this module is called directly."""


def valid_work_factor_limit(limit: object) -> bool:
    """Whether a work-factor limit is an integer in 1-22 (Reader contract §3). ``bool`` is not an integer here."""
    return isinstance(limit, int) and not isinstance(limit, bool) and 1 <= limit <= 22


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


def _wipe(*buffers: bytearray | None) -> None:
    """Zeroes key material and partial plaintext held in a bytearray (F6); immutable bytes cannot be zeroed."""
    for b in buffers:
        if b is not None:
            b[:] = bytes(len(b))


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
    # A limit outside 1-22 is refused, never read as "no limit".
    if not valid_work_factor_limit(max_scrypt_work_factor):
        raise AgeError(
            "header", f"max_scrypt_work_factor must be an integer from 1 to 22, not {max_scrypt_work_factor!r}"
        )
    whole_length = len(data)
    # The header is at most 64 KiB, so only that much is ever searched or parsed.
    data = bytes(memoryview(data)[:MAX_HEADER_BYTES])
    pos = 0

    def line() -> tuple[str, int]:
        nonlocal pos
        end = data.find(b"\n", pos)
        if end < 0:
            raise AgeError(
                "header",
                "the header is over 64 KiB" if whole_length > MAX_HEADER_BYTES else "the header is not terminated",
            )
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
            if whole_length - pos < 16:
                raise AgeError("header", "the payload nonce is missing or short")
            return Header(stanzas, data[: start + 3], mac, pos)
        if not text.startswith("-> "):
            raise AgeError("header", "expected a stanza or the MAC line")
        if len(stanzas) >= MAX_STANZAS:
            raise AgeError("header", f"the header has more than {MAX_STANZAS} stanzas")
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


def _unwrap_x25519(header: Header, identities: list[str]) -> bytearray | None:
    """The file key an X25519 stanza unwraps with one of the identities, or None. A bad identity is noMatch (E002)."""
    keys = []
    for identity in identities:
        scalar = decode_identity(identity) if isinstance(identity, str) else None
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
                return bytearray(file_key)
    return None


def _unwrap_scrypt(stanza: Stanza, passphrase: str) -> bytearray | None:
    """The file key the passphrase unwraps from the scrypt stanza, or None."""
    salt = b"age-encryption.org/v1/scrypt" + base64.b64decode(stanza.args[0] + "==")
    key = bytearray(
        Scrypt(salt=salt, length=32, n=2 ** int(stanza.args[1]), r=8, p=1).derive(passphrase.encode("utf-8"))
    )
    try:
        file_key = _open(bytes(key), _ZERO_NONCE, stanza.body)
    finally:
        _wipe(key)
    return bytearray(file_key) if file_key is not None and len(file_key) == 16 else None


def check_key(key: object) -> AgeKey:
    """Checks what the key provider returned (encrypted packages §5.1). Not a mapping (or an AgeKey): noKey (E001).
    A member of the wrong type, or a file key that is not 16 bytes: noMatch (E002). ``file_key`` and the spec's
    ``fileKey`` are both accepted; an awaitable is refused (this binding's provider is synchronous)."""
    if isinstance(key, AgeKey):
        return key
    if inspect.isawaitable(key):
        if hasattr(key, "close"):
            key.close()  # a coroutine that is never awaited
        raise AgeError("noKey", "the key provider returned an awaitable; this binding takes a synchronous provider")
    if not isinstance(key, Mapping):
        raise AgeError("noKey", "the key provider returned no key")
    identities = key.get("identities")
    passphrase = key.get("passphrase")
    file_key = key.get("file_key", key.get("fileKey"))
    if identities is not None and (
        not isinstance(identities, (list, tuple)) or not all(isinstance(i, str) for i in identities)
    ):
        raise AgeError("noMatch", "the key provider returned identities that are not a list of strings")
    if passphrase is not None and not isinstance(passphrase, str):
        raise AgeError("noMatch", "the key provider returned a passphrase that is not a string")
    if file_key is not None and not isinstance(file_key, (bytes, bytearray, memoryview)):
        raise AgeError("noMatch", "the key provider returned a file key that is not bytes")
    return AgeKey(
        identities=list(identities or []),
        passphrase=passphrase,
        file_key=bytes(file_key) if file_key is not None else None,
    )


def _mac_ok(header: Header, file_key: bytes | bytearray) -> bool:
    mac = hmac.new(_hkdf(bytes(file_key), b"", b"header"), header.header_no_mac, sha256).digest()
    return hmac.compare_digest(mac, header.mac)


def find_file_key(header: Header, key: object) -> bytearray:
    """Finds the file key and verifies the header MAC with it (encrypted packages §5.1, §5.2 steps 4-5). A key's
    kinds are tried in order: identities, then the passphrase, then the file key; the first whose file key verifies
    the MAC wins. ``noKey`` when no kind the key has is one the file uses; ``noMatch`` or ``mac`` when one was tried
    and failed. The caller zeroes the returned key."""
    k = check_key(key)
    if k.file_key is not None and len(k.file_key) != 16:
        raise AgeError("noMatch", "the file key from the key provider is not 16 bytes")
    tried = False
    mac_failed = False

    def accept(file_key: bytearray | None) -> bytearray | None:
        nonlocal mac_failed
        if file_key is None:
            return None
        if _mac_ok(header, file_key):
            return file_key
        mac_failed = True
        _wipe(file_key)
        return None

    if k.identities and any(s.type == "X25519" for s in header.stanzas):
        tried = True
        found = accept(_unwrap_x25519(header, k.identities))
        if found is not None:
            return found
    stanza = next((s for s in header.stanzas if s.type == "scrypt"), None)
    if k.passphrase is not None and stanza is not None:
        tried = True
        found = accept(_unwrap_scrypt(stanza, k.passphrase))
        if found is not None:
            return found
    if k.file_key is not None:
        tried = True
        found = accept(bytearray(k.file_key))
        if found is not None:
            return found
    if not tried:
        raise AgeError(
            "noKey",
            "the key provider returned keys of kinds no stanza in the file uses"
            if k.identities or k.passphrase is not None
            else "the key provider returned no key",
        )
    if mac_failed:
        raise AgeError("mac", "the header MAC does not verify")
    raise AgeError("noMatch", "no key from the key provider unwraps a stanza")


def verify_mac(header: Header, file_key: bytes | bytearray) -> None:
    """Verifies the header MAC with a constant-time compare."""
    if not _mac_ok(header, file_key):
        raise AgeError("mac", "the header MAC does not verify")


def plaintext_length(ciphertext_length: int, max_bytes: int) -> int:
    """The plaintext length of a STREAM payload, from its length alone (encrypted packages §5.2 step 6): every chunk
    but the last is 64 KiB + 16, and the last is 16 to 64 KiB + 16. ``payload`` for a length no payload can have;
    ``limit`` over ``max_bytes``; both before any decryption."""
    full = CHUNK + TAG
    chunks = max(1, -(-ciphertext_length // full))
    last = ciphertext_length - (chunks - 1) * full
    if last < TAG or (last == TAG and chunks > 1):
        raise AgeError(
            "payload", "the payload length is impossible: the final chunk is missing, short or empty after a full chunk"
        )
    length = ciphertext_length - chunks * TAG
    if length > max_bytes:
        raise AgeError("limit", f"the decrypted payload would be {length} bytes, over {max_bytes}")
    return length


def decrypt_payload(
    data: bytes, header: Header, file_key: bytes | bytearray, max_bytes: int | None = None
) -> bytearray:
    """Decrypts and authenticates the whole STREAM payload into one buffer of the exact size, computed first.
    Returns nothing until every chunk has authenticated; on failure the partial plaintext is zeroed."""
    start = header.payload_start + 16
    view = memoryview(data)
    out = bytearray(plaintext_length(len(data) - start, DEFAULT_MAX_BYTES if max_bytes is None else max_bytes))
    key = bytearray(_hkdf(bytes(file_key), bytes(view[header.payload_start : start]), b"payload"))
    aead = ChaCha20Poly1305(bytes(key))
    _wipe(key)
    pos = start
    written = 0
    counter = 0
    try:
        while True:
            last = len(data) - pos <= CHUNK + TAG
            sealed = view[pos:] if last else view[pos : pos + CHUNK + TAG]
            try:
                plain = aead.decrypt(counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00"), sealed, None)
            except InvalidTag:
                raise AgeError(
                    "payload",
                    "the final chunk does not authenticate, or is missing"
                    if last
                    else f"chunk {counter} does not authenticate",
                ) from None
            out[written : written + len(plain)] = plain
            written += len(plain)
            if last:
                return out
            pos += CHUNK + TAG
            counter += 1
    except BaseException:
        _wipe(out)
        raise


class AgeDecryptor:
    """The decryptor a host passes to ``read_package`` to enable the optional feature ``encryption``."""

    @staticmethod
    def parse_header(data: bytes, max_scrypt_work_factor: int = 20) -> Header:
        return parse_header(data, max_scrypt_work_factor)

    @staticmethod
    def decrypt(data: bytes, header: Header, key: object, max_bytes: int | None = None) -> bytearray:
        """``key`` is an AgeKey, or what a key provider returns: a mapping with ``identities``, ``passphrase`` and
        ``file_key`` (or the spec's ``fileKey``), one or more of them. ``max_bytes`` defaults to the Reader's default."""
        file_key = find_file_key(header, key)
        try:
            return decrypt_payload(data, header, file_key, max_bytes)
        finally:
            _wipe(file_key)


AGE_DECRYPTOR = AgeDecryptor()
