"""Package spec §4.10 and Reader contract §9: readingOrder and upTo. The corpus covers the rules; these cover what it
cannot.

The same tests as moca-reader-typescript's test/reading-order.test.js.
"""

from __future__ import annotations

import json
from pathlib import Path

from moca_reader import LexicalBackend, Library, MemoryStoreBackend, Search, StoreScope, package_state, read_package

B = "https://example.org/c#"
HEAD = "@prefix skos: <http://www.w3.org/2004/02/skos/core#> .\n@prefix c: <https://example.org/c#> .\n"


def node(*concepts: str) -> str:
    bound = "moca:\n  concepts:\n" + "".join(f"    - iri: {B}{c}\n" for c in concepts) if concepts else ""
    return f"---\ntype: Note\ntitle: A\n{bound}---\n\n# A\n\nText.\n"


def make_package(root: Path, structure: str, nodes: dict[str, str] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    manifest = {"id": "https://example.com/t", "version": "1.0.0", "title": "T", "readingOrder": f"{B}Path"}
    (root / "moca.json").write_text(json.dumps(manifest))
    (root / "structure.ttl").write_text(HEAD + structure)
    for path, text in (nodes or {"a.md": node()}).items():
        (root / "content" / path).parent.mkdir(parents=True, exist_ok=True)
        (root / "content" / path).write_text(text)
    return root


def test_an_empty_list_or_a_list_with_no_collection_type_does_not_resolve(tmp_path: Path) -> None:
    empty = read_package(make_package(tmp_path / "e", "c:Path a skos:OrderedCollection ; skos:memberList () .\n"))
    assert [d.code for d in empty.diagnostics] == ["M014_READING_ORDER_UNRESOLVED"]
    assert empty.reading_order is None
    untyped = read_package(make_package(tmp_path / "u", "c:A a skos:Concept .\nc:Path skos:memberList ( c:A ) .\n"))
    assert "M014_READING_ORDER_UNRESOLVED" in [d.code for d in untyped.diagnostics]


def test_a_narrower_cycle_does_not_stop_placement_and_each_concept_keeps_its_first_position(tmp_path: Path) -> None:
    ttl = (
        "c:A a skos:Concept ; skos:narrower c:B .\nc:B a skos:Concept ; skos:narrower c:A .\nc:C a skos:Concept .\n"
        "c:Path a skos:OrderedCollection ; skos:memberList ( c:A c:C c:B ) .\n"
    )
    r = read_package(make_package(tmp_path, ttl, {"a.md": node("A"), "b.md": node("B"), "c.md": node("C")}))
    assert r.reading_order == f"{B}Path"
    library = Library().add(r)
    # B is a member at index 2, but sits under A at index 0, so it passes at upTo A.
    records = Search(library, LexicalBackend(library)).search("text", limit=10, up_to=f"{B}A")
    assert sorted(x["node"]["path"] for x in records) == ["a.md", "b.md"]


def test_a_package_state_carries_the_reading_order_and_a_store_search_with_pushdown_applies_it(
    tmp_path: Path,
) -> None:
    ttl = (
        "c:A a skos:Concept .\nc:B a skos:Concept .\nc:__proto__ a skos:Concept .\n"
        "c:Path a skos:OrderedCollection ; skos:memberList ( c:A c:B ) .\n"
    )
    r = read_package(make_package(tmp_path, ttl, {"a.md": node("A"), "b.md": node("B"), "p.md": node("__proto__")}))
    state = json.loads(json.dumps(package_state(r)))
    assert state["readingOrder"] == {
        "iri": f"{B}Path",
        "members": [f"{B}A", f"{B}B"],
        "positions": {f"{B}A": 0, f"{B}B": 1},
    }
    store = MemoryStoreBackend(filter_pushdown=True).ingest(Library().add(r))
    # With pushdown the Reader would fetch only the limit; upTo has no pushdown filter, so it must fetch more.
    records = Search(StoreScope([state]), store).search("text", limit=2, up_to=f"{B}A")
    assert sorted(x["node"]["path"] for x in records) == ["a.md", "p.md"]
