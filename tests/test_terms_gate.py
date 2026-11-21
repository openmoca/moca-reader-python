"""What the terms gate covers, and hiding a closed package (moca-spec Reader contract §9.4, §10, §15.3-15.4;
ADR-0041).

The conformance corpus tests the same rules across Readers; these tests add what it cannot see: what an embedder
receives at ingest, and the store search's own resolver. The same tests as moca-reader-typescript's
test/terms-gate.test.js.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from spec_paths import MOCA_SPEC

from moca_reader import (
    LexicalBackend,
    Library,
    MemoryStoreBackend,
    Search,
    StoreScope,
    directory_resolver,
    package_state,
    read_package,
)
from moca_reader.schemas import validate_against

CORPUS = MOCA_SPEC / "conformance"
M = "fixtures/terms/mention/"
T = "https://example.org/conformance/terms-structure#"
NOW = datetime(2026, 11, 21, tzinfo=UTC)
PROVIDER = {"ai": {"destination": "provider", "use": "answer"}}


def at(path: str) -> str:
    return str(CORPUS / path)


def library(paths: list[str], **options: Any) -> Library:
    lib = Library(clock=lambda: NOW)
    for p in paths:
        result = read_package(at(p), trust_root=at("fixtures/trust-root.json"), clock=lambda: NOW, **options)
        assert result.valid, p
        lib.add(result)
    return lib


class RecordingEmbedder:
    """An embedder that records every text it is given."""

    name = "recording"
    dimensions = 2

    def __init__(self) -> None:
        self.seen: list[str] = []

    def embed(self, texts: list[str], role: str) -> list[list[float]]:
        self.seen += texts
        return [[1.0, 0.0] for _ in texts]


def test_ingest_for_a_provider_never_sends_closed_text_to_the_embedder_nor_stores_it() -> None:
    lib = library([M + "open", M + "closed-named", M + "closed-hidden"])
    embedder = RecordingEmbedder()
    store = MemoryStoreBackend(embedder).ingest(lib, terms={"destination": "provider"})
    # The fixtures' episodes share their words, so count: only the open package's one unit reaches the embedder.
    assert len(embedder.seen) == 1
    assert {r["hit"]["record"]["package"]["id"] for r in store.records} == {
        "https://example.com/conformance/terms-mention-open"
    }
    [u004] = store.ingest_diagnostics
    assert (u004.code, u004.excluded, u004.hidden) == ("U004_TERMS_EXCLUDED", {"ai.allowed.provider": 3}, 2)

    device = MemoryStoreBackend(RecordingEmbedder()).ingest(lib, terms={"destination": "device"})
    assert len(device.records) == 4
    assert device.ingest_diagnostics == []
    assert len(MemoryStoreBackend().ingest(lib).records) == 4


def test_ingest_applies_the_host_terms_limits_as_floors() -> None:
    lib = library([M + "open"])
    store = MemoryStoreBackend().ingest(lib, terms={"destination": "host"}, terms_limits={"allowed": {"host": False}})
    assert store.records == []
    assert store.ingest_diagnostics[0].excluded == {"ai.allowed.host": 1}


def test_a_search_u004_carries_the_counts_by_reason_and_the_hidden_count() -> None:
    lib = library([M + "closed-hidden", "fixtures/terms/node-tightens"])
    search = Search(lib, LexicalBackend(lib))
    records = search.search("lantern", limit=10, terms=PROVIDER)
    assert [r["node"]["path"] for r in records] == ["public.md"]
    u004 = next(d for d in search.diagnostics if d.code == "U004_TERMS_EXCLUDED")
    assert (u004.excluded, u004.hidden) == ({"ai.allowed.provider": 3}, 2)


def test_a_store_search_leaves_hidden_packages_out_of_superseded_by_from_the_package_states() -> None:
    lib = library([M + "supersede/v1", M + "supersede/v2"])
    store = MemoryStoreBackend(filter_pushdown=False).ingest(lib)
    states = [package_state(p.result) for p in lib.packages]
    search = Search(StoreScope(states, lambda: NOW), store)
    provider = search.search("lantern", limit=10, include_all=True, terms=PROVIDER)
    assert [r["package"]["version"] for r in provider] == ["1.0.0"]
    assert provider[0]["trust"]["superseded"] is True
    assert "supersededBy" not in provider[0]["trust"]
    device = search.search(
        "lantern", limit=10, include_all=True, terms={"ai": {"destination": "device", "use": "answer"}}
    )
    v1 = next(r for r in device if r["package"]["version"] == "1.0.0")
    assert v1["trust"]["supersededBy"] == ["https://example.com/conformance/terms-mention-supersede@2.0.0"]


def test_the_catalogue_names_a_closed_package_with_exactly_six_fields_and_has_no_entry_for_a_hidden_one() -> None:
    lib = library([M + "open", M + "closed-named", M + "closed-hidden"])
    entries = lib.catalogue(PROVIDER)
    assert all(validate_against("catalogueEntry", e) == [] for e in entries)
    assert [e["id"] for e in entries] == [
        "https://example.com/conformance/terms-mention-closed-named",
        "https://example.com/conformance/terms-mention-open",
    ]
    assert sorted(entries[0]) == ["closedBy", "id", "publisher", "signed", "title", "version"]
    assert "hidden" not in json.dumps(entries), "the hidden package is named nowhere"
    # Without a request every package has an open entry.
    assert len(lib.catalogue()) == 3


def test_structure_for_builds_the_structure_from_the_packages_not_closed_for_the_request() -> None:
    lib = library(["fixtures/terms/structure/open", "fixtures/terms/structure/closed"])
    gated = lib.structure_for(PROVIDER)
    topic = gated.concept(f"{T}Topic")
    assert topic is not None and topic["labels"] == {"en": "Harbours"} and "definition" not in topic
    assert gated.concept(f"{T}Closed") is None
    assert [r["package"]["id"] for r in gated.nodes(f"{T}Topic", include="narrower")] == []
    # No request, or one without an ai part, is the whole structure.
    assert lib.structure_for() is lib.structure
    assert lib.structure_for({"rating": {"explicit": False}}) is lib.structure
    device = lib.structure_for({"ai": {"destination": "device"}}).concept(f"{T}Topic")
    assert device is not None and device["definition"] == "Text a provider may not receive."


def test_a_composing_package_that_speaks_for_its_member_can_hide_it_an_unsigned_one_cannot() -> None:
    members = directory_resolver([at("fixtures/terms/composite/member")])
    signed = library(["fixtures/terms/composite/hides"], resolve_member=members)
    # The member allows every destination, so it is never closed, and so never hidden: mention changes nothing.
    assert len(signed.catalogue({"ai": {"destination": "host"}})) == 2
    device = {"ai": {"destination": "device", "use": "answer"}}
    [r] = Search(signed, LexicalBackend(signed)).search("lantern", terms=device)
    assert r["terms"]["ai"]["allowed"]["mention"] == {"value": False, "decidedBy": "composite"}
    unsigned = library(["fixtures/terms/composite/hides-unsigned"], resolve_member=members)
    [r2] = Search(unsigned, LexicalBackend(unsigned)).search("lantern", terms=device)
    assert r2["terms"]["ai"]["allowed"]["mention"] == {"value": True, "decidedBy": "platform"}
