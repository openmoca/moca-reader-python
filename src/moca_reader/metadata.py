"""Flat metadata from a citation record, for stores and frameworks that need flat fields.

The names are the consuming guide's ("Feeding your own retrieval stack", moca-spec docs/guides/consuming.md),
which the Reader interface §7 requires a binding to use when its framework needs flat metadata. Values are
strings, numbers, booleans or lists of strings; a field with no value is left out, since many stores refuse null.
"""

from __future__ import annotations

from typing import Any

from .citation import CitationRecord

FLAT_FIELDS = (
    "moca_package_id",
    "moca_package_version",
    "moca_package_digest",
    "moca_node_id",
    "moca_node_digest",
    "moca_node_ref",
    "moca_status",
    "moca_in_force_until",
    "moca_stale_after",
    "moca_superseded",
    "moca_attested_reviews",
    "moca_signed",
    "moca_audience",
    "moca_concepts",
    "moca_evidence_matched",
)


def flat_metadata(record: CitationRecord) -> dict[str, Any]:
    """The consuming guide's ``moca_*`` fields for one citation record.

    ``moca_attested_reviews`` is how many attested reviews the node has; ``moca_evidence_matched`` is true when
    every checked evidence quote was found in its source, false when one was not, and absent when none was checked.
    """
    package, node, trust = record["package"], record["node"], record["trust"]
    checked = [e["matched"] for e in record.get("evidence", []) if isinstance(e.get("matched"), bool)]
    values: dict[str, Any] = {
        "moca_package_id": package.get("id"),
        "moca_package_version": package.get("version"),
        "moca_package_digest": package.get("digest"),
        "moca_node_id": node.get("id"),
        "moca_node_digest": node.get("digest"),
        "moca_node_ref": node.get("ref"),
        "moca_status": trust.get("status"),
        "moca_in_force_until": trust.get("validUntil"),
        "moca_stale_after": trust.get("staleAfter"),
        "moca_superseded": trust.get("superseded"),
        "moca_attested_reviews": len(trust.get("attestedReviews", [])),
        "moca_signed": package.get("signed"),
        "moca_audience": record.get("audience"),
        "moca_concepts": list(record["concepts"]) if record.get("concepts") else None,
        "moca_evidence_matched": all(checked) if checked else None,
    }
    return {k: v for k, v in values.items() if v is not None}
