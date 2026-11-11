"""Strict Ed25519 encodings (attestations §5).

Ed25519 libraries disagree on edge cases: small-order and mixed-order points, and non-canonical encodings. MOCA
removes the disagreement before a library verifies anything: the public key A and the signature's R must each be
the canonical encoding of a point of prime order L, and S must be less than L. With those, the cofactored and
cofactorless verification equations agree, so every Reader reaches the same answer.
"""

from __future__ import annotations

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, P - 2, P)) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)

_Point = tuple[int, int, int, int]
_IDENTITY: _Point = (0, 1, 1, 0)


def _add(p: _Point, q: _Point) -> _Point:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * _D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(k: int, p: _Point) -> _Point:
    q = _IDENTITY
    while k:
        if k & 1:
            q = _add(q, p)
        p = _add(p, p)
        k >>= 1
    return q


def _is_identity(p: _Point) -> bool:
    x, y, z, _ = p
    return x % P == 0 and (y - z) % P == 0


def _decode(encoded: bytes) -> _Point | None:
    """RFC 8032 §5.1.3, refusing non-canonical encodings (y ≥ p, or x = 0 with the sign bit set)."""
    if len(encoded) != 32:
        return None
    n = int.from_bytes(encoded, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (_D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    if (v * x * x - u) % P != 0:
        x = x * _SQRT_M1 % P
        if (v * x * x - u) % P != 0:
            return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def is_prime_order_point(encoded: bytes) -> bool:
    """The canonical encoding of a point of order L: not the identity, no small-order component."""
    point = _decode(encoded)
    return point is not None and not _is_identity(point) and _is_identity(_mul(L, point))


def strict_encodings(public_key: bytes, signature: bytes) -> bool:
    """Attestations §5: A and R are canonical points of order L, and S < L."""
    if len(signature) != 64:
        return False
    return (
        int.from_bytes(signature[32:], "little") < L
        and is_prime_order_point(public_key)
        and is_prime_order_point(signature[:32])
    )
