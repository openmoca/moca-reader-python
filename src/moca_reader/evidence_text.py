"""Evidence checks against sources inside the package (Reader contract §7).

W3C Web Annotation says selector text "MUST be normalized", with HTML and XML tags removed and character
entities replaced. These are MOCA's exact normalisation rules per source type, so every Reader reaches the
same answer. Positions count Unicode code points of the normalised text.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from ._js import js_split_ws, js_trim

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
            cp = int(e[2:], 16) if e[1] in "xX" else int(e[1:], 10)
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


def check_selector(selector: dict[str, Any], raw: str, kind: str, prepared: str | None = None) -> bool | None:
    """Checks one selector against a source's raw text; None when it cannot be checked against this source."""
    if selector.get("type") == "FragmentSelector":
        conforms = selector.get("conformsTo")
        if not _MEDIA_FRAGMENTS.match(conforms if isinstance(conforms, str) else "") or kind != "webvtt":
            return None
        window = media_time_range(selector.get("value"))
        if window is None:
            return False
        return any(window[0] < c.end and window[1] > c.start for c in webvtt(raw)[0])
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
