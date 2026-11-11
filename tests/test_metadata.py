"""flat_metadata uses exactly the consuming guide's field names."""

from __future__ import annotations

import re

from spec_paths import EXAMPLES, MOCA_SPEC

from moca_reader import FLAT_FIELDS, Library, flat_metadata, read_package

GUIDE = (MOCA_SPEC / "docs" / "guides" / "consuming.md").read_text("utf-8")


def test_the_fields_are_the_consuming_guides() -> None:
    section = GUIDE.split("## Feeding your own retrieval stack", 1)[1].split("\n## ", 1)[0]
    named = set(re.findall(r"`(moca_[a-z_]+)`", section))
    assert sorted(FLAT_FIELDS) == sorted(named)


def test_a_signed_reviewed_record_gives_every_field_it_has() -> None:
    pkg = read_package(EXAMPLES / "support-kb", trust_root=MOCA_SPEC / "fixtures" / "signing-keys" / "trust-root.json")
    record = Library().add(pkg).get("https://example.com/moca/support-kb#refund-window.md")
    assert record is not None
    flat = flat_metadata(record)
    assert flat["moca_node_ref"] == "https://example.com/moca/support-kb@4.2.0#refund-window.md"
    assert flat["moca_package_digest"] == pkg.digest
    assert (flat["moca_signed"], flat["moca_attested_reviews"], flat["moca_evidence_matched"]) == (True, 1, True)
    assert flat["moca_audience"] == "public"
    assert set(flat) <= set(FLAT_FIELDS)
    assert all(v is not None for v in flat.values())
