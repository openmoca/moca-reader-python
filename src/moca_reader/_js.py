"""Behaviours of the reference Reader (JavaScript) that every Reader matches.

These are the places where Python's defaults differ from JavaScript's, and so from what the
reference Reader and the conformance corpus expect.
"""

from __future__ import annotations

import base64
import math
import re
from datetime import UTC, datetime
from typing import Any


def utf16_key(text: str) -> bytes:
    """Sort key for JavaScript's string order: UTF-16 code units, not code points."""
    return text.encode("utf-16-be", "surrogatepass")


def js_sorted(values: Any, key: Any = None) -> list[Any]:
    """``sorted`` in JavaScript's string order."""
    if key is None:
        return sorted(values, key=utf16_key)
    return sorted(values, key=lambda v: utf16_key(key(v)))


_FULL_DATE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})\Z")
_DATE_TIME = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})\Z"
)


def parse_date(value: Any) -> datetime | None:
    """A date or date-time as a UTC instant, or None (package spec §4.4, attestations §6).

    A full date (YYYY-MM-DD) is 00:00:00Z on that day. A date-time is RFC 3339 and carries an offset (Z or
    ±hh:mm); without one it does not parse, so no Reader guesses a time zone. Anything else does not parse.
    """
    if not isinstance(value, str):
        return None
    try:
        m = _FULL_DATE.match(value)
        if m:
            return datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=UTC)
        if not _DATE_TIME.match(value):
            return None
        parsed = datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC)


def effective_window(
    package_from: Any, package_until: Any, node_from: Any, node_until: Any
) -> tuple[Any, Any, datetime | None, datetime | None]:
    """The node's validity window (package spec §4.4): the intersection of the package's window and its own.

    A bound that does not parse, or a window whose end is not after its start, is ignored. Returns the bounds as
    written (or None) and as instants (or None).
    """

    def window(start: Any, end: Any) -> tuple[datetime | None, datetime | None]:
        f, u = parse_date(start), parse_date(end)
        if f is not None and u is not None and u <= f:
            return None, None
        return f, u

    pf, pu = window(package_from, package_until)
    nf, nu = window(node_from, node_until)
    from_pick = (node_from, nf) if nf is not None and (pf is None or nf >= pf) else (package_from, pf)
    until_pick = (node_until, nu) if nu is not None and (pu is None or nu <= pu) else (package_until, pu)
    return (
        from_pick[0] if from_pick[1] is not None else None,
        until_pick[0] if until_pick[1] is not None else None,
        from_pick[1],
        until_pick[1],
    )


_BASE64_JUNK = re.compile(r"[^A-Za-z0-9+/\-_]")


def b64decode(text: str) -> bytes:
    """Base64 decoded as Node's ``Buffer.from(text, 'base64')`` does: leniently, never raising."""
    clean = _BASE64_JUNK.sub("", text.split("=", 1)[0]).replace("-", "+").replace("_", "/")
    clean = clean[: len(clean) - (len(clean) % 4 == 1)]
    try:
        return base64.b64decode(clean + "=" * (-len(clean) % 4))
    except ValueError:  # pragma: no cover - the input is already clean
        return b""


def math_round(value: float) -> float:
    """JavaScript's ``Math.round``: the nearest integer, and halves go towards +infinity (-2.5 gives -2)."""
    if math.isnan(value) or math.isinf(value):
        return value
    floor = math.floor(value)
    return float(floor + 1 if value - floor >= 0.5 else floor)


def round_scaled(value: float, scale: float) -> float:
    """``Math.round(value * scale) / scale``, as the reference Reader rounds scores."""
    return math_round(value * scale) / scale


def truthy(value: Any) -> bool:
    """JavaScript truthiness: empty lists and objects are truthy; 0, NaN, "" and null are not."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0 and not math.isnan(value)
    if isinstance(value, str):
        return value != ""
    return True


def get(obj: Any, key: str) -> Any:
    """``obj?.key`` on parsed JSON or YAML: None unless ``obj`` is an object with that key."""
    return obj.get(key) if isinstance(obj, dict) else None


def is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def json_loads(text: str, unique_keys: bool = False) -> Any:
    """``JSON.parse``: NaN and Infinity are not JSON. With ``unique_keys``, a repeated member name raises ValueError
    (I-JSON, RFC 7493)."""
    import json

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError(f'member "{key}" appears more than once')
            out[key] = value
        return out

    if unique_keys:
        return json.loads(text, parse_constant=_no_constants, object_pairs_hook=pairs)
    return json.loads(text, parse_constant=_no_constants)


def number_to_string(value: float | int) -> str:
    """ECMAScript ``Number.prototype.toString`` for finite numbers."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits, _, exp = f"{abs(value):.17e}".partition("e")
    # The shortest round-tripping digits, as repr gives them.
    r = repr(abs(value))
    mantissa, _, e = r.partition("e")
    exponent = int(e) if e else 0
    if "." in mantissa:
        whole, frac = mantissa.split(".")
    else:
        whole, frac = mantissa, ""
    if frac == "0":
        frac = ""
    s_digits = (whole + frac).lstrip("0")
    n = exponent + len(whole) - (len(whole + frac) - len((whole + frac).lstrip("0")))
    s_digits = s_digits.rstrip("0") or "0"
    k = len(s_digits)
    del digits, exp
    if k <= n <= 21:
        out = s_digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = s_digits[:n] + "." + s_digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s_digits
    else:
        e_val = n - 1
        e_str = f"e{'+' if e_val >= 0 else '-'}{abs(e_val)}"
        out = s_digits[0] + ("." + s_digits[1:] if k > 1 else "") + e_str
    return sign + out


def stringify(value: Any) -> str:
    """``JSON.stringify`` with no spacing, for comparing JSON documents as the reference Reader does."""
    import json

    if value is None or isinstance(value, (bool, str)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)):
        return (
            "null" if isinstance(value, float) and (math.isnan(value) or math.isinf(value)) else number_to_string(value)
        )
    if isinstance(value, list):
        return "[" + ",".join(stringify(v) for v in value) + "]"
    if isinstance(value, dict):
        return (
            "{" + ",".join(f"{json.dumps(str(k), ensure_ascii=False)}:{stringify(v)}" for k, v in value.items()) + "}"
        )
    return "null"


def decode_uri_component(text: str) -> str:
    """``decodeURIComponent``: raises ValueError on a malformed escape, as JavaScript throws URIError."""
    from urllib.parse import unquote_to_bytes

    if re.search(r"%(?![0-9A-Fa-f]{2})", text):
        raise ValueError("URI malformed")
    try:
        return unquote_to_bytes(text).decode("utf-8")
    except UnicodeDecodeError as err:
        raise ValueError("URI malformed") from err


def posix_normalize(path: str) -> str:
    """Node's ``path.posix.normalize``: keeps a trailing slash, collapses repeated slashes, '' gives '.'."""
    if path == "":
        return "."
    absolute = path.startswith("/")
    trailing = path.endswith("/")
    parts: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            elif not absolute:
                parts.append("..")
            continue
        parts.append(seg)
    out = "/".join(parts)
    if not out and not absolute:
        out = "."
    if out and trailing:
        out += "/"
    return ("/" + out) if absolute else out


def posix_dirname(path: str) -> str:
    import posixpath

    d = posixpath.dirname(path.rstrip("/") if path != "/" else path)
    return d or "."


def posix_join(*parts: str) -> str:
    joined = "/".join(p for p in parts if p != "")
    return posix_normalize(joined) if joined else "."


def js_string(value: Any, present: bool = True) -> str:
    """``String(value)``; ``present=False`` stands for JavaScript's ``undefined``."""
    if not present:
        return "undefined"
    if value is None:
        return "null"
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return number_to_string(value)
    if isinstance(value, list):
        return ",".join("" if v is None else js_string(v) for v in value)
    return "[object Object]"


def timestamp(value: Any) -> float:
    """``Date.parse(value)`` in milliseconds, or NaN, so comparisons with it are false as in JavaScript."""
    parsed = parse_date(value if isinstance(value, str) else js_string(value))
    return parsed.timestamp() * 1000 if parsed is not None else math.nan


# Package spec §2: white space is ECMAScript's. Python's str.strip() and str.split() use another set.
JS_WHITESPACE = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"


def js_trim(text: str) -> str:
    """String.prototype.trim."""
    return text.strip(JS_WHITESPACE)


def js_split_ws(text: str) -> list[str]:
    """``text.trim().split(/\\s+/)`` without empty parts, as ``str.split()`` but with ECMAScript white space."""
    return [p for p in re.split(f"[{JS_WHITESPACE}]+", text) if p]
