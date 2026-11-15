"""Package spec §5.7, "Alternates".

Media descriptions of one node that carry the same content on timelines that line up stretch by stretch. Each entry
of ``sync`` starts a stretch of the reference, from its ``at`` up to the next entry's ``at``; the last runs to the end.
A stretch with an offset is on the alternate at ``t + offset``; one whose offset is None is not in the alternate.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class _Stretch:
    start: float  # on the reference
    end: float
    offset: float | None

    @property
    def lo(self) -> float:  # on the alternate
        return self.start + (self.offset or 0)

    @property
    def hi(self) -> float:
        return self.end + (self.offset or 0)


def default_sync() -> list[dict[str, Any]]:
    """The sync of an alternate that gives none: the reference's timeline unchanged."""
    return [{"at": 0, "offset": 0}]


def _stretches(sync: list[dict[str, Any]]) -> list[_Stretch]:
    return [
        _Stretch(e["at"], sync[i + 1]["at"] if i + 1 < len(sync) else math.inf, e["offset"]) for i, e in enumerate(sync)
    ]


def sync_problem(sync: list[dict[str, Any]]) -> str | None:
    """Why a sync list cannot be used (``at`` out of order, or stretches that overlap on the alternate), or None."""
    for i in range(1, len(sync)):
        if not sync[i]["at"] > sync[i - 1]["at"]:
            return 'its "at" values are not in strictly increasing order'
    mapped = sorted((s for s in _stretches(sync) if s.offset is not None), key=lambda s: s.lo)
    for a, b in itertools.pairwise(mapped):
        if a.hi > b.lo:
            return "two of its stretches overlap on the alternate's timeline"
    return None


def to_alternate(sync: list[dict[str, Any]], t: float) -> float | None:
    """A moment on the reference, on the alternate; None when its stretch is not in the alternate."""
    held = [s for s in _stretches(sync) if s.start <= t]
    if not held:
        return None
    s = held[-1]
    return t + s.offset if s.offset is not None and t < s.end else None


def to_reference(sync: list[dict[str, Any]], t: float) -> float | None:
    """A moment on the alternate, on the reference; None when it lies in no stretch."""
    for s in _stretches(sync):
        if s.offset is not None and s.lo <= t < s.hi:
            return t - s.offset
    return None


def range_to_reference(sync: list[dict[str, Any]], window: tuple[float, float]) -> tuple[float, float] | None:
    """A time range on the alternate, on the reference, when its start and end lie in one stretch; else None.

    The end may equal the stretch's last moment. A range with no end keeps none.
    """
    start, end = window
    for s in _stretches(sync):
        if s.offset is not None and s.lo <= start < s.hi:
            if end == math.inf:
                return start - s.offset, math.inf
            return (start - s.offset, end - s.offset) if end <= s.hi else None
    return None


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _within(t: float, d: dict[str, Any]) -> bool:
    duration = d.get("duration")
    if not _number(t) or t < 0:
        return False
    return not isinstance(duration, (int, float)) or not _number(duration) or t <= duration


def map_time(record: dict[str, Any], from_source: str, to_source: str, t: float) -> float | None:
    """Reader interface §4: the same moment on another media description of the record's node, or None.

    A description maps a moment on its own timeline to itself; two alternates of one reference map through it.
    """
    node = record.get("node") if isinstance(record, dict) else None
    media = node.get("media") if isinstance(node, dict) else None
    media = media if isinstance(media, list) else []
    a = next((d for d in media if d.get("source") == from_source), None)
    b = next((d for d in media if d.get("source") == to_source), None)
    if a is None or b is None or not _number(t) or not _within(t, a):
        return None
    if a is b:
        return t
    ref_id = a.get("alternateOf", a.get("source"))
    if b.get("alternateOf", b.get("source")) != ref_id:
        return None
    ref = next((d for d in media if d.get("source") == ref_id), None)
    if ref is None:
        return None
    on_ref = t if "alternateOf" not in a else to_reference(a.get("sync") or default_sync(), t)
    if on_ref is None or not _within(on_ref, ref):
        return None
    out = on_ref if "alternateOf" not in b else to_alternate(b.get("sync") or default_sync(), on_ref)
    return out if out is not None and _within(out, b) else None
