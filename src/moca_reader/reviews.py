"""Review status (package spec §11, Reader contract §7, moca-spec ADR-0017)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def review_status_of(reviews: Sequence[Any] | None, signed: bool) -> str:
    """``none``, ``unverified`` (reviews in an unsigned package), ``approved`` (signed, an accurate review and none
    against) or ``disputed`` (signed, and a current review says needs-change or inaccurate)."""
    if not reviews:
        return "none"
    if not signed:
        return "unverified"
    if any(r.outcome != "accurate" for r in reviews):
        return "disputed"
    return "approved"
