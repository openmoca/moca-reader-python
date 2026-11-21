"""Creators' terms (package spec §4.14, Reader contract §15): checking, resolving and the terms gate."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from moca_reader import LexicalBackend, Library, Search, SearchHooks, read_package
from moca_reader.terms import (
    UNSET,
    check_terms,
    gate_reasons,
    loosened_nodes,
    node_entry,
    rating_of,
    record_terms,
    resolve_ai,
    resolve_export,
    rights_of,
    terms_request,
)

NODE = "---\ntype: Note\ntitle: {title}\n---\n\n# {title}\n\nText about refunds.\n"
NOW = datetime(2026, 11, 21, tzinfo=UTC)


def package(root: Path, manifest: dict[str, Any], files: dict[str, str]) -> str:
    root.mkdir(parents=True)
    (root / "moca.json").write_text(json.dumps({"id": "https://example.com/t", "version": "1.0.0", **manifest}))
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    return str(root)


def problems(terms: Any) -> set[str]:
    return {f"{p['code']} {p['path']}" for p in check_terms(terms)}


def pkg(terms: Any) -> dict[str, Any]:
    return {"terms": terms, "authority": "unverified"}


# Checking (package spec §4.14)


def test_absent_terms_have_no_problems_and_valid_terms_none() -> None:
    assert check_terms(UNSET) == []
    assert problems({"ai": {"allowed": {"provider": False}, "answerSources": "work"}}) == set()


def test_unknown_strings_and_members_are_u003_everything_else_u001() -> None:
    found = problems({"ai": {"answerSources": "edge", "allowed": {"edge": True, "training": None}}, "extra": 1})
    assert found == {
        "U003_TERMS_UNKNOWN_VALUE ai.answerSources",
        "U003_TERMS_UNKNOWN_VALUE ai.allowed.edge",
        "U001_TERMS_INVALID ai.allowed.training",
        "U003_TERMS_UNKNOWN_VALUE extra",
    }
    # A container of the wrong type is reported once, at the container.
    assert problems({"ai": {"allowed": False}}) == {"U001_TERMS_INVALID ai.allowed"}


def test_checks_the_schema_cannot_express() -> None:
    found = problems(
        {
            "rating": {
                "typicalAgeRange": "16-12",
                "contentRating": [{"scheme": "a", "value": "1"}, {"scheme": "a", "value": "2"}],
            },
            "rights": {"copyright": {"year": "2026-2024"}},
            "nodes": [{"paths": ["content/a.md"], "rights": {"copyright": {"year": "2020-2019"}}}],
        }
    )
    assert found == {
        "U001_TERMS_INVALID rating.typicalAgeRange",
        "U001_TERMS_INVALID rating.contentRating",
        "U001_TERMS_INVALID rights.copyright.year",
        "U001_TERMS_INVALID nodes.0.rights.copyright.year",
    }
    assert problems({"rights": {"copyright": {"year": "2024-2026"}}}) == set()


def test_a_looser_node_is_reported_and_the_package_value_stands() -> None:
    terms = {
        "ai": {"allowed": {"provider": False}, "providerRequires": ["noTraining"]},
        "nodes": [{"paths": ["content/a.md"], "ai": {"allowed": {"provider": True}, "providerRequires": []}}],
    }
    assert [x["path"] for x in loosened_nodes(terms)] == ["nodes.0.ai.allowed.provider", "nodes.0.ai.providerRequires"]
    ai = resolve_ai(pkg(terms), "a.md")
    assert ai["allowed.provider"] == {"value": False, "decidedBy": "package"}
    assert ai["providerRequires"] == {"value": ["noTraining"], "decidedBy": "package"}


# Resolving (contract §15.3)


def test_platform_defaults_and_no_level_loosens_them() -> None:
    ai = resolve_ai(pkg({"ai": {"allowed": {"training": True}}}), "a.md")
    assert ai["allowed.training"] == {"value": False, "decidedBy": "platform"}
    assert ai["allowed.device"] == {"value": True, "decidedBy": "platform"}
    assert ai["answerSources"] == {"value": "model", "decidedBy": "platform"}
    assert ai["providerRequires"] == {"value": [], "decidedBy": "platform"}


def test_stricter_wins_and_records_the_level() -> None:
    terms = {
        "ai": {"allowed": {"host": False}},
        "nodes": [{"paths": ["content/notes/"], "ai": {"answerSources": "work"}}],
    }
    composite = {"ai": {"allowed": {"machineTranslation": False}}}
    ai = resolve_ai(pkg(terms), "notes/x.md", {"allowed": {"device": False}}, [composite])
    assert ai["allowed.host"] == {"value": False, "decidedBy": "package"}
    assert ai["answerSources"] == {"value": "work", "decidedBy": "node"}
    assert ai["allowed.machineTranslation"] == {"value": False, "decidedBy": "composite"}
    assert ai["allowed.device"] == {"value": False, "decidedBy": "host"}
    # The node entry is the longest matching path or prefix.
    assert resolve_ai(pkg(terms), "other.md")["answerSources"]["decidedBy"] == "platform"


def test_malformed_and_unknown_values_count_as_the_strictest() -> None:
    # A boolean field set to a number is not true: JavaScript's SameValueZero, not Python's 1 == True.
    ai = resolve_ai(pkg({"ai": {"allowed": {"provider": 1}, "answerSources": "edge", "providerRequires": "x"}}), "a.md")
    assert ai["allowed.provider"]["value"] is False
    assert ai["answerSources"]["value"] == "work"
    assert ai["providerRequires"]["value"] == ["(malformed)"]
    strictest = resolve_ai(pkg({"ai": {"allowed": False}}), "a.md")
    assert all(strictest[f"allowed.{d}"]["value"] is False for d in ("device", "host", "provider"))
    # A `nodes` that cannot say which nodes it means counts for every node, at the strictest.
    for nodes in ({}, ["x"], [{"paths": "content/a.md"}]):
        everyone = resolve_ai(pkg({"nodes": nodes}), "b.md")
        assert everyone["allowed.device"] == {"value": False, "decidedBy": "node"}
        assert everyone["answerSources"]["value"] == "work"


def test_export_resolves_from_package_and_composites() -> None:
    assert resolve_export(pkg({})) == {"value": True, "decidedBy": "platform"}
    assert resolve_export(pkg({"rights": {"export": {"allowed": False}}})) == {"value": False, "decidedBy": "package"}
    assert resolve_export(pkg({"rights": "no"})) == {"value": False, "decidedBy": "package"}
    assert resolve_export(pkg({}), [{"rights": {"export": {"allowed": "yes"}}}]) == {
        "value": False,
        "decidedBy": "composite",
    }


def test_rights_of_takes_the_node_entry_then_the_package() -> None:
    terms = {
        "rights": {"copyright": {"year": "2024"}},
        "nodes": [
            {"paths": ["content/photo.md"], "rights": {"license": "CC-BY-4.0", "copyright": {"year": "2025"}}},
            {"paths": ["content/bad.md"], "rights": {"license": "MIT", "copyright": {"year": "1"}}},
        ],
    }
    found = check_terms(terms)
    assert rights_of(terms, found, "CC-BY-SA-4.0", "photo.md") == {
        "license": "CC-BY-4.0",
        "copyright": {"year": "2025"},
    }
    assert rights_of(terms, found, "CC-BY-SA-4.0", "ep1.md") == {
        "license": "CC-BY-SA-4.0",
        "copyright": {"year": "2024"},
    }
    # A value with a problem at or under its path is skipped, and the package's is used.
    assert rights_of(terms, found, None, "bad.md") == {"license": "MIT", "copyright": {"year": "2024"}}
    assert rights_of(UNSET, [], None, "a.md") == {}


# The terms gate (contract §15.4)


def gate(request: dict[str, Any], terms: Any, path: str = "a.md") -> list[str]:
    return gate_reasons(request, resolve_ai(pkg(terms), path), rating_of(terms, path))


def test_ai_requests() -> None:
    no_provider = {"ai": {"allowed": {"provider": False}}}
    assert gate({"ai": {"destination": "provider"}}, no_provider) == ["ai.allowed.provider"]
    assert gate({"ai": {"destination": "device"}}, no_provider) == []
    # An unknown or missing destination is the strictest, provider.
    assert gate({"ai": {"destination": "moon"}}, no_provider) == ["ai.allowed.provider"]
    conditions = {"ai": {"providerRequires": ["noTraining", "noRetention"]}}
    assert gate({"ai": {"destination": "provider", "conditions": ["noTraining"]}}, conditions) == [
        "ai.providerRequires"
    ]
    assert gate({"ai": {"destination": "provider", "conditions": ["noTraining", "noRetention"]}}, conditions) == []
    assert gate({"ai": {"destination": "host", "use": "train"}}, {}) == ["ai.allowed.training"]
    assert gate(
        {"ai": {"destination": "host", "use": "translate"}}, {"ai": {"allowed": {"machineTranslation": False}}}
    ) == ["ai.allowed.machineTranslation"]


def test_rating_requests() -> None:
    rated = {"rating": {"explicit": False, "contentRating": [{"scheme": "uk", "value": "PG"}]}}
    assert gate({"rating": {"explicit": False}}, {}) == ["rating.unrated"]
    assert gate({"rating": {"explicit": False, "allowUnrated": True}}, {}) == []
    assert gate({"rating": {"explicit": False, "schemes": {"uk": ["U", "PG"]}}}, rated) == []
    assert gate({"rating": {"schemes": {"uk": ["U"]}}}, rated) == ["rating.uk"]
    # Rated only under a scheme the host did not list: unrated for this host.
    only_other = {"rating": {"contentRating": [{"scheme": "us", "value": "G"}]}}
    assert gate({"rating": {"schemes": {"uk": ["U"]}}}, only_other) == ["rating.unrated"]
    # A malformed rating counts as explicit and outside every listed scheme.
    assert gate({"rating": {"explicit": False, "schemes": {"uk": ["U"]}}}, {"rating": "pg"}) == [
        "rating.explicit",
        "rating.uk",
    ]
    # A feed's explicit: false counts only when the host accepts feed ratings.
    feed = {"rating": {"explicit": False, "declaredBy": "feed"}}
    assert gate({"rating": {"explicit": False}}, feed) == ["rating.unrated"]
    assert gate({"rating": {"explicit": False, "acceptFeedRatings": True}}, feed) == []
    # A request this version cannot honour in full removes every record.
    assert gate({"rating": {"explicit": False, "maxAge": 12}}, rated) == ["rating.request"]
    assert gate({"rating": {"schemes": []}}, rated) == ["rating.request"]


def test_record_terms_shape() -> None:
    terms = {"rating": "x", "nodes": [{"paths": ["content/a.md"], "rating": {"explicit": True}}]}
    assert node_entry(terms, "a.md") is terms["nodes"][0]
    out = record_terms("packager", resolve_ai(pkg(terms), "b.md"), rating_of(terms, "b.md"), resolve_export(pkg(terms)))
    assert out["authority"] == "packager"
    assert out["ai"]["allowed"]["device"] == {"value": True, "decidedBy": "platform"}
    assert out["rating"] == {"explicit": True}
    assert out["rights"] == {"export": {"value": True, "decidedBy": "platform"}}


# Reading and searching


def test_read_package_exposes_terms_as_written(tmp_path: Path) -> None:
    terms = {"ai": {"allowed": {"provider": False}}, "rights": {"export": {"allowed": False}}}
    result = read_package(
        package(
            tmp_path / "p",
            {"title": "T", "terms": terms, "datePackaged": "2026-11-19T18:30:00+01:00", "license": "MIT"},
            {"content/a.md": NODE.format(title="A")},
        )
    )
    assert result.valid
    assert [d.code for d in result.diagnostics] == []
    assert result.terms == {"declared": terms, "problems": [], "authority": "unverified"}
    assert result.date_packaged == "2026-11-19T18:30:00+01:00"
    record = Library(clock=lambda: NOW).add(result).citations()[0]
    assert record["package"]["datePackaged"] == "2026-11-19T18:30:00+01:00"
    assert record["node"]["license"] == "MIT"


def test_a_manifest_that_is_not_an_object_is_m002_and_has_no_terms(tmp_path: Path) -> None:
    root = tmp_path / "p"
    root.mkdir()
    (root / "moca.json").write_text("[1, 2]")
    result = read_package(str(root))
    assert not result.valid
    assert "M002_MANIFEST_SCHEMA" in [d.code for d in result.diagnostics]
    assert result.manifest is None and result.terms is None


def test_the_terms_gate_in_a_search(tmp_path: Path) -> None:
    terms = {"nodes": [{"paths": ["content/private.md"], "ai": {"allowed": {"provider": False}}}]}
    result = read_package(
        package(
            tmp_path / "p",
            {"title": "T", "terms": terms},
            {"content/public.md": NODE.format(title="Public"), "content/private.md": NODE.format(title="Private")},
        )
    )
    library = Library(clock=lambda: NOW).add(result)
    search = Search(library, LexicalBackend(library))
    # Without a terms request, terms remove nothing and records carry no terms.
    plain = search.search("refunds", limit=10)
    assert {r["node"]["path"] for r in plain} == {"public.md", "private.md"}
    assert all("terms" not in r for r in plain)
    gated = search.search("refunds", limit=10, terms={"ai": {"destination": "provider"}})
    assert [r["node"]["path"] for r in gated] == ["public.md"]
    assert gated[0]["terms"]["authority"] == "unverified"
    assert [d.code for d in search.diagnostics] == ["U004_TERMS_EXCLUDED"]
    assert "ai.allowed.provider: 1" in search.diagnostics[0].message
    # A host limit is a floor: it can only tighten.
    floored = Search(library, LexicalBackend(library), terms_limits={"allowed": {"provider": False}})
    assert floored.search("refunds", limit=10, terms={"ai": {"destination": "provider"}}) == []


def test_de_duplication_keeps_spans_that_differ_only_in_their_end(tmp_path: Path) -> None:
    result = read_package(package(tmp_path / "p", {"title": "T"}, {"content/a.md": NODE.format(title="A")}))
    library = Library(clock=lambda: NOW).add(result)

    def egress(candidates: list[dict[str, Any]], ctx: Any) -> list[dict[str, Any]]:
        base = candidates[0]
        start = base["span"]["start"]
        return [
            {**base, "span": {"start": start, "end": start + 4}},
            {**base, "span": {"start": start, "end": start + 8}},
            {**base, "span": {"start": start, "end": start + 8}},
        ]

    records = Search(library, LexicalBackend(library), hooks=SearchHooks(egress=egress)).search("refunds")
    assert [r["span"]["end"] - r["span"]["start"] for r in records] == [4, 8]


def test_terms_request_for_an_app_that_hands_records_to_a_model() -> None:
    assert terms_request() == {"ai": {"destination": "provider"}}
    assert terms_request("host", ["noTraining"]) == {"ai": {"destination": "host", "conditions": ["noTraining"]}}
    rating = {"rating": {"explicit": False}}
    assert terms_request(terms=rating) == {**rating, "ai": {"destination": "provider"}}
    own = {"ai": {"destination": "device", "use": "summarise"}}
    assert terms_request(terms=own) == own
    with pytest.raises(ValueError, match="destination"):
        terms_request("moon")
