"""BM25 over plain text, shared by the lexical and in-memory store backends.

Tokens. Every Reader's built-in lexical backend tokenises the same way, so they return the same results:
1. NFKC-normalise the text, then lower-case it as package spec §6.3 does (one code point at a time).
2. Letters, digits and combining marks are word characters; anything else separates words. Keeping marks inside
   words keeps Devanagari, Arabic and other scripts with vowel signs whole.
3. Scripts written without spaces (Chinese, Japanese kana, Thai, Lao, Khmer, Myanmar) are split into units, each
   character with the combining marks after it, and indexed as each unit and each pair of neighbouring units.
No stemming: hosts that need it supply their own lexical backend.
"""

from __future__ import annotations

import math
import unicodedata
from collections.abc import Sequence
from typing import Any

from .._js import round_scaled, utf16_key
from ..unicode import lower_code_point, normalize

UNSPACED = (
    (0x0E00, 0x0EFF),  # Thai, Lao
    (0x1000, 0x109F),  # Myanmar
    (0x1780, 0x17FF),  # Khmer
    (0x3040, 0x30FF),  # Hiragana, Katakana
    (0x31F0, 0x31FF),  # Katakana phonetic extensions
    (0x3400, 0x4DBF),  # CJK extension A
    (0x4E00, 0x9FFF),  # CJK unified ideographs
    (0xF900, 0xFAFF),  # CJK compatibility ideographs
    (0x20000, 0x3FFFF),  # CJK extensions B and later
)


def _unspaced(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in UNSPACED)


def _word_char(ch: str) -> bool:
    return len(ch) == 1 and unicodedata.category(ch)[0] in "LNM"


def _mark(ch: str) -> bool:
    return len(ch) == 1 and unicodedata.category(ch)[0] == "M"


def tokens(text: str) -> list[str]:
    out: list[str] = []
    run: list[str] = []
    run_unspaced = False

    def flush() -> None:
        if not run:
            return
        if not run_unspaced:
            out.append("".join(run))
        else:
            for i, unit in enumerate(run):
                out.append(unit)
                if i + 1 < len(run):
                    out.append(unit + run[i + 1])
        run.clear()

    for ch in normalize("NFKC", text):
        c = lower_code_point(ch)
        if not _word_char(c):
            flush()
            continue
        u = _unspaced(ord(c))
        if u and run_unspaced and run and _mark(c):
            run[-1] += c
            continue
        if run and u != run_unspaced:
            flush()
        run_unspaced = u
        run.append(c)
    flush()
    return out


def count_terms(text: str) -> tuple[dict[str, int], int]:
    """A text's term frequencies and length in tokens: all BM25 needs of it."""
    t = tokens(text)
    terms: dict[str, int] = {}
    for term in t:
        terms[term] = terms.get(term, 0) + 1
    return terms, len(t)


def bm25(docs: Sequence[dict[str, Any]], query: str, k1: float = 1.2, b: float = 0.75) -> list[dict[str, Any]]:
    """``docs`` are ``{item, text, key}``; key breaks ties. Best first, zero scores dropped."""
    return bm25_counted(
        [{"item": d["item"], "key": d["key"], "counts": count_terms(d["text"])} for d in docs], query, k1, b
    )


def bm25_counted(docs: Sequence[dict[str, Any]], query: str, k1: float = 1.2, b: float = 0.75) -> list[dict[str, Any]]:
    """bm25() over documents already counted (``{item, key, counts}``), so a backend can count each document once.
    The same arithmetic in the same order, so scores are identical."""
    q = list(dict.fromkeys(tokens(query)))
    if not q or not docs:
        return []
    avg = sum(d["counts"][1] for d in docs) / len(docs) or 1
    df = {term: sum(1 for d in docs if term in d["counts"][0]) for term in q}
    scored = []
    for d in docs:
        terms, length = d["counts"]
        score = 0.0
        for term in q:
            f = terms.get(term, 0)
            if f == 0:
                continue
            idf = math.log(1 + (len(docs) - df[term] + 0.5) / (df[term] + 0.5))
            score += idf * ((f * (k1 + 1)) / (f + k1 * (1 - b + (b * length) / avg)))
        scored.append({"item": d["item"], "key": d["key"], "score": round_scaled(score, 1e4)})
    kept = [s for s in scored if s["score"] > 0]
    kept.sort(key=lambda s: (-s["score"], utf16_key(s["key"])))
    return [{"item": s["item"], "score": s["score"]} for s in kept]
