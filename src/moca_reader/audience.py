"""Audience (package spec §5.3, Reader contract §8, moca-spec ADR-0016).

- A node's label is its ``moca.audience``, a non-empty string.
- A translation with no ``moca.audience`` of its own takes the label of the node's default representation.
- A label that is present but not a non-empty string is malformed: it never matches any audience set, even when the
  host allows unlabelled content.
- When the host supplies an audience set, a record with no label is outside it unless the host sets
  ``allow_unlabelled``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def audience_of(node: Any, rep: Any) -> tuple[str | None, bool]:
    """(label, invalid) for a representation."""
    own = rep.frontmatter.get("moca")
    if isinstance(own, dict) and "audience" in own:
        source: Any = own
    else:
        reps = getattr(node, "representations", None) or []
        source = reps[0].frontmatter.get("moca") if reps else None
    if not isinstance(source, dict) or "audience" not in source:
        return None, False
    value = source["audience"]
    return (value, False) if isinstance(value, str) and value != "" else (None, True)


def audience_allowed(
    label: str | None, invalid: bool, audiences: Sequence[str] | None, allow_unlabelled: bool = False
) -> bool:
    """Whether a label passes the host's audience set."""
    if audiences is None:
        return True
    if invalid:
        return False
    if label is None:
        return allow_unlabelled
    return label in audiences


def record_allowed(record: Any, audiences: Sequence[str] | None, allow_unlabelled: bool = False) -> bool:
    """The audience rule for a citation record, for the gate and store backends."""
    label = record.get("audience")
    return audience_allowed(
        label if isinstance(label, str) else None, record.get("audienceInvalid") is True, audiences, allow_unlabelled
    )
