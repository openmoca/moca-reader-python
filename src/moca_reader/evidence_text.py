"""Evidence checks against sources inside the package (Reader contract §7).

W3C Web Annotation says selector text "MUST be normalized", with HTML and XML tags removed and character
entities replaced. These are MOCA's exact normalisation rules per source type, so every Reader reaches the
same answer. Positions count Unicode code points of the normalised text.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ._js import js_split_ws, js_trim

if TYPE_CHECKING:
    from collections.abc import Callable

_KINDS = [
    (re.compile(r"\.(txt|text)\Z", re.I | re.A), "text"),
    (re.compile(r"\.(md|markdown)\Z", re.I | re.A), "markdown"),
    (re.compile(r"\.(html|htm)\Z", re.I | re.A), "html"),
    (re.compile(r"\.vtt\Z", re.I | re.A), "webvtt"),
]
_MEDIA_FRAGMENTS = re.compile(r"^https?://www\.w3\.org/TR/media-frags/?\Z")
_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'", "nbsp": "\u00a0"}
_ENTITY = re.compile(r"&(#x[0-9a-f]+|#[0-9]+|[a-z]+);", re.I | re.A)


def source_kind(path: str) -> str | None:
    for pattern, kind in _KINDS:
        if pattern.search(path):
            return kind
    return None


def _decode_entities(text: str) -> str:
    def entity(m: re.Match[str]) -> str:
        e = m[1]
        if e[0] == "#":
            # Leading zeros count for nothing; more digits than any code point has is not a code point.
            hexadecimal = e[1] in "xX"
            digits = (e[2:] if hexadecimal else e[1:]).lstrip("0") or "0"
            if len(digits) > (6 if hexadecimal else 7):
                return m[0]
            cp = int(digits, 16 if hexadecimal else 10)
            return chr(cp) if cp <= 0x10FFFF else m[0]
        return _ENTITIES.get(e.lower(), m[0])

    return _ENTITY.sub(entity, text)


def markdown_text(source: str) -> str:
    """Markdown to text: images and links become their text; heading and list markers go; *, _ and ` go."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", source)
    lines = [
        re.sub(
            r"^[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*(?:[-*+]|[0-9]+[.)])[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+",
            "",
            re.sub(
                r"^[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*#{1,6}[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+",
                "",
                line,
            ),
        )
        for line in text.split("\n")
    ]
    return re.sub(r"[*_`]", "", "\n".join(lines))


def html_text(source: str) -> str:
    """HTML to text: script and style elements removed, tags removed, entities decoded."""
    without = re.sub(
        r"<(script|style)\b[^>]*>[\s\S]*?</\1[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*>",
        "",
        source,
        flags=re.I | re.A,
    )
    return _decode_entities(re.sub(r"<[^>]*>", "", without))


def _number(text: str) -> float:
    try:
        return float(text) if js_trim(text) else 0.0
    except ValueError:
        return math.nan


def _seconds(ts: str) -> float:
    t = js_trim(ts)
    m = re.match(r"^(?:([0-9]+):)?([0-9]{1,2}):([0-9]{2}(?:\.[0-9]+)?)\Z", t)
    if m:
        return _number(m[1] or "0") * 3600 + _number(m[2]) * 60 + _number(m[3])
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\Z", t)
    return _number(m[1]) if m else math.nan


@dataclass
class Cue:
    start: float
    end: float
    text: str


def webvtt(source: str) -> tuple[list[Cue], str]:
    """WebVTT cues and their payload text, cue tags removed and entities decoded, joined with LF."""
    blocks = re.split(r"\n{2,}", re.sub(r"\r\n?", "\n", source))
    cues: list[Cue] = []
    for block in blocks[1:]:
        lines = block.split("\n")
        at = next((i for i, line in enumerate(lines) if "-->" in line), -1)
        if at < 0:
            continue
        start_text, _, rest = lines[at].partition("-->")
        start = _seconds(start_text)
        end = _seconds((js_split_ws(rest) or [""])[0])
        text = "\n".join(_decode_entities(re.sub(r"<[^>]*>", "", line)) for line in lines[at + 1 :])
        if math.isfinite(start) and math.isfinite(end):
            cues.append(Cue(start, end, text))
    return cues, "\n".join(c.text for c in cues)


def normalised_text(raw: str, kind: str) -> str:
    if kind == "markdown":
        return markdown_text(raw)
    if kind == "html":
        return html_text(raw)
    if kind == "webvtt":
        return webvtt(raw)[1]
    return raw


def media_time_range(value: Any) -> tuple[float, float] | None:
    """A Media Fragments temporal value ``t=start[,end]`` (seconds or hh:mm:ss), or None."""
    m = re.search(r"(?:^|&)t=(?:npt:)?([^,&]*)(?:,([^&]*))?", "" if value is None else str(value))
    if not m:
        return None
    start = 0.0 if m[1] == "" else _seconds(m[1])
    end = math.inf if m[2] is None else _seconds(m[2])
    if not math.isfinite(start) or math.isnan(end) or end < start:
        return None
    return start, end


def _is_integer(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())


def selector_matches(selector: Any, text: str) -> bool | None:
    """None when the selector type is not checked."""
    kind = selector.get("type") if isinstance(selector, dict) else None
    if kind == "TextQuoteSelector":
        exact = selector.get("exact")
        if not isinstance(exact, str) or exact == "":
            return False
        prefix = selector["prefix"] if isinstance(selector.get("prefix"), str) else ""
        suffix = selector["suffix"] if isinstance(selector.get("suffix"), str) else ""
        # One search for prefix + exact + suffix: the same answer as checking each occurrence of exact, without
        # rescanning the text for every one.
        return (prefix + exact + suffix) in text
    # Contract §7: a TextPositionSelector on its own proves only that its offsets are in range, so it is not
    # checked: `matched` stays absent.
    if kind == "TextPositionSelector":
        return None
    return None


def is_media_time_range(selector: Any) -> bool:
    """A FragmentSelector that conforms to Media Fragments: a time range in audio or video."""
    if not isinstance(selector, dict) or selector.get("type") != "FragmentSelector":
        return False
    conforms = selector.get("conformsTo")
    return bool(_MEDIA_FRAGMENTS.match(conforms if isinstance(conforms, str) else ""))


# Contract §7: in a refined quote, each run of these characters counts as one space.
_QUOTE_SPACE = re.compile(r"[\t\n\f\r ]+")
_SPACE_CHARS = frozenset("\t\n\f\r ")


def _js_number(x: float) -> float | int:
    """A whole number as an int, so JSON writes it as JavaScript does."""
    return int(x) if float(x).is_integer() else x


def occurrences(text: str, needle: str) -> list[int]:
    """Every start index of ``needle`` in ``text``, overlapping ones included, in one linear pass (Knuth-Morris-Pratt)."""
    m = len(needle)
    if m == 0:
        return []
    fail = [0] * m
    k = 0
    for i in range(1, m):
        while k > 0 and needle[i] != needle[k]:
            k = fail[k - 1]
        if needle[i] == needle[k]:
            k += 1
        fail[i] = k
    out: list[int] = []
    k = 0
    for i, ch in enumerate(text):
        while k > 0 and ch != needle[k]:
            k = fail[k - 1]
        if ch == needle[k]:
            k += 1
        if k == m:
            out.append(i - m + 1)
            k = fail[k - 1]
    return out


def _sparse_table(values: list[float], pick: Callable[[float, float], float]) -> Callable[[int, int], float]:
    """A range-minimum (or maximum) table: query(lo, hi) over values[lo..hi] in O(1)."""
    levels = [values]
    w = 1
    while 2 * w <= len(values):
        prev = levels[-1]
        levels.append([pick(prev[i], prev[i + w]) for i in range(len(prev) - w)])
        w *= 2

    def query(lo: int, hi: int) -> float:
        k = (hi - lo + 1).bit_length() - 1
        return pick(levels[k][lo], levels[k][hi - (1 << k) + 1])

    return query


def locate_quote(cues: list[Cue], window: tuple[float, float], quote: dict[str, Any]) -> tuple[float, float] | None:
    """Contract §7: where a refining quote is spoken in a time range.

    The covered text is the payloads of the cues the range overlaps, in file order, joined with LF, with each run of
    white space (the five ASCII characters) as one space, the quote's parts too. A cue is touched when a non-space
    character of ``exact`` comes from it. Of every occurrence, the one whose touched cues span the shortest time wins,
    the earliest on a tie. Returns the earliest start and the latest end of the touched cues, or None when the quote
    is not in the covered text. Contract §3: linear in the covered text and the quote.
    """
    if not isinstance(quote.get("exact"), str):
        return None

    def part(v: Any) -> str:
        return _QUOTE_SPACE.sub(" ", v) if isinstance(v, str) else ""

    exact = part(quote["exact"])
    if all(ch in _SPACE_CHARS for ch in exact):
        return None
    prefix = part(quote.get("prefix"))
    needle = prefix + exact + part(quote.get("suffix"))
    covered = [c for c in cues if window[0] < c.end and window[1] > c.start]
    chars: list[str] = []
    owner: list[int] = []
    for i, c in enumerate(covered):
        for ch in ("\n" if i > 0 else "") + c.text:
            if ch in _SPACE_CHARS:
                if owner and owner[-1] == -1:
                    continue
                chars.append(" ")
                owner.append(-1)
            else:
                chars.append(ch)
                owner.append(i)
    text = "".join(chars)
    n = len(owner)
    # The owner of the first non-space character at or after each position, and of the last at or before it.
    nxt = [-1] * (n + 1)
    for i in range(n - 1, -1, -1):
        nxt[i] = owner[i] if owner[i] >= 0 else nxt[i + 1]
    prv = [-1] * n
    for i in range(n):
        prv[i] = owner[i] if owner[i] >= 0 else (prv[i - 1] if i > 0 else -1)
    # Cues with text, in order: the touched cues of a span are those between its first and last owner.
    rank = [-1] * len(covered)
    filled: list[int] = []
    for o in owner:
        if o >= 0 and rank[o] < 0:
            rank[o] = len(filled)
            filled.append(o)
    if not filled:
        return None
    earliest = _sparse_table([covered[c].start for c in filled], min)
    latest = _sparse_table([covered[c].end for c in filled], max)
    best: tuple[float, float] | None = None
    for at in occurrences(text, needle):
        a = at + len(prefix)
        b = a + len(exact)
        first, last = nxt[a], prv[b - 1]
        if first < 0 or last < 0 or rank[first] > rank[last]:
            continue
        span = (earliest(rank[first], rank[last]), latest(rank[first], rank[last]))
        if (
            best is None
            or span[1] - span[0] < best[1] - best[0]
            or (span[1] - span[0] == best[1] - best[0] and span[0] < best[0])
        ):
            best = span
    return best


def check_selector(
    selector: dict[str, Any],
    raw: str,
    kind: str,
    prepared: str | None = None,
    duration: float | None = None,
    to_reference: Callable[[tuple[float, float]], tuple[float, float] | None] | None = None,
    report: dict[str, Any] | None = None,
    cues: list[Cue] | None = None,
) -> bool | None:
    """Checks one selector against a source's raw text; None when it cannot be checked against this source.

    ``cues`` are the source's WebVTT cues, when the caller has parsed them already.
    """
    if selector.get("type") == "FragmentSelector":
        conforms = selector.get("conformsTo")
        if not _MEDIA_FRAGMENTS.match(conforms if isinstance(conforms, str) else "") or kind != "webvtt":
            return None
        parsed = media_time_range(selector.get("value"))
        # Package spec §5.7: a range on an alternate is checked on its reference's timeline; one that does not map fails.
        window = to_reference(parsed) if parsed is not None and to_reference is not None else parsed
        if window is None:
            return False
        if cues is None:
            cues = webvtt(raw)[0]
        if not any(window[0] < c.end and window[1] > c.start for c in cues):
            return False
        # Contract §7: the range lies within the media, bounded by the latest cue end or the declared duration.
        if window[1] != float("inf"):
            bound = max((c.end for c in cues), default=float("-inf"))
            if duration is not None:
                bound = max(bound, duration)
            if window[1] > bound:
                return False
        # Contract §7: a range refined by a quote matches only when the quote is in the cues it covers.
        refined = selector.get("refinedBy")
        if not isinstance(refined, dict) or refined.get("type") != "TextQuoteSelector":
            return True
        located = locate_quote(cues, window, refined)
        if located is None:
            return False
        # On an alternate, back to the cited source's timeline by the stretch's offset.
        assert parsed is not None
        offset = parsed[0] - window[0]
        if report is not None:
            report["located"] = {"start": _js_number(located[0] + offset), "end": _js_number(located[1] + offset)}
        return True
    # The quote is normalised as the source is, so markup in either never decides a match.
    quote = _normalise_quote(selector, kind) if selector.get("type") == "TextQuoteSelector" else selector
    return selector_matches(quote, prepared if prepared is not None else normalised_text(raw, kind))


def _normalise_quote(selector: dict[str, Any], kind: str) -> dict[str, Any]:
    # A quote from captions is cue text already; Markdown and HTML quotes lose markup as their sources do.
    if kind not in ("markdown", "html"):
        return selector
    return {
        **selector,
        **{
            k: normalised_text(selector[k], kind)
            for k in ("exact", "prefix", "suffix")
            if isinstance(selector.get(k), str)
        },
    }
