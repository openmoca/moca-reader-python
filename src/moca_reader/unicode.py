"""Lower-casing and normalisation, defined once.

Package spec §6.3: each code point is replaced with its Unicode simple lowercase mapping, one at a
time, with no language or context rules. İ (U+0130) becomes i, and capital sigma always becomes small sigma. Python's
``str.lower`` is the full mapping (İ gives i + U+0307), so it is applied one code point at a time
and corrected where the full and simple mappings differ.
"""

from __future__ import annotations

import unicodedata


def lower_code_point(ch: str) -> str:
    """The simple lowercase mapping of one code point."""
    lowered = ch.lower()
    if lowered == "i̇":
        return "i"
    # Any other multi-code-point result has no simple mapping: the code point stays as it is.
    return lowered if len(lowered) == 1 else ch


def simple_lowercase(text: str) -> str:
    """A string lower-cased one code point at a time."""
    return "".join(lower_code_point(ch) for ch in text)


def normalize(form: str, text: str) -> str:
    """``unicodedata.normalize`` that never raises: lone surrogates and noncharacters stay in place."""
    try:
        return unicodedata.normalize(form, text)  # type: ignore[arg-type]
    except (ValueError, UnicodeError):  # pragma: no cover - CPython keeps them as they are
        return text
