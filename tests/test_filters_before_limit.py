"""Reader contract §9.2, "Filters come before the limit"."""

from __future__ import annotations

from typing import Any

import pytest
from spec_paths import MOCA_SPEC

from moca_reader import LexicalBackend, Library, Search, read_package
from moca_reader.resolver import directory_resolver

RF = "https://example.com/conformance/ranked-filter"
DIR = MOCA_SPEC / "conformance" / "fixtures" / "ranked-filter"


def ranked_filter() -> Library:
    result = read_package(DIR / "course", resolve_member=directory_resolver([DIR]))
    return Library(allow_unsigned_relations=True).add(result)


class Unfiltered:
    """A backend that ignores every filter but honours the limit, and counts what it is asked for."""

    features = ("lexical",)

    def __init__(self, library: Library) -> None:
        self.diagnostics: list[Any] = []
        self.lexical = LexicalBackend(library)
        self.digests = [p.result.digest for p in library.packages]
        self.asked: list[int] = []

    def search(self, query: str, limit: int, filters: dict[str, Any]) -> list[dict[str, Any]]:
        self.asked.append(limit)
        return self.lexical.search(query, limit, {"digests": self.digests, "exclude": []})


def test_records_far_down_the_ranking_are_found_whatever_the_backend() -> None:
    library = ranked_filter()
    everything = Search(library, LexicalBackend(library)).search("lantern", limit=1000)
    assert [r["package"]["id"] for r in everything].index(f"{RF}-step-1") == 240
    unfiltered = Unfiltered(library)
    for backend in (LexicalBackend(library), unfiltered):
        records = Search(library, backend).search("lantern", limit=6, up_to=f"{RF}-step-1")
        assert [r["node"]["path"] for r in records] == ["a.md", "b.md", "c.md", "d.md", "e.md", "f.md"]
    # It asked again, doubling, until the limit was met.
    assert unfiltered.asked == [18, 36, 72, 144, 288]


def test_a_host_bound_stops_a_search_and_reports_s010() -> None:
    library = ranked_filter()
    bounded = Search(library, Unfiltered(library), max_candidates=100)
    assert bounded.search("lantern", limit=6, up_to=f"{RF}-step-1") == []
    assert [d.code for d in bounded.diagnostics] == ["S010_SEARCH_TRUNCATED"]
    roomy = Search(library, Unfiltered(library), max_candidates=300)
    assert len(roomy.search("lantern", limit=6, up_to=f"{RF}-step-1")) == 6
    assert roomy.diagnostics == []
    with pytest.raises(ValueError):
        Search(library, Unfiltered(library), max_candidates=0)


def test_a_pushed_down_filter_never_changes_a_score() -> None:
    library = ranked_filter()
    everything = Search(library, LexicalBackend(library)).search("lantern", limit=1000)
    score_of = {r["node"]["ref"]: r["score"] for r in everything}
    scoped = Search(library, LexicalBackend(library)).search("lantern", limit=6, scope=f"{RF}#topic")
    assert len(scoped) == 6
    for r in scoped:
        assert r["score"] == score_of[r["node"]["ref"]]
