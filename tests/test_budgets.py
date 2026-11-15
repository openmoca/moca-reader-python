"""Reader contract §3: work stays bounded on hostile compositions and structures.

The same tests as moca-reader-typescript's test/budgets.test.js. Each sets a time budget, and the composition tests a
memory budget, that the quadratic versions broke by orders of magnitude.
"""

from __future__ import annotations

import json
import time
import tracemalloc
from typing import TYPE_CHECKING, Any

from moca_reader import LexicalBackend, Library, Search, directory_resolver, package_state, read_package

if TYPE_CHECKING:
    from pathlib import Path

ID = "https://example.com/budget"


def _pkg(root: Path, manifest: dict[str, Any], files: dict[str, str] | None = None) -> None:
    (root / "content").mkdir(parents=True, exist_ok=True)
    (root / "moca.json").write_text(
        json.dumps({"mocaVersion": "0.7", "version": "1.0.0", "language": "en", **manifest}), "utf-8"
    )
    for path, body in (files or {}).items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(body, "utf-8")


def _node(title: str) -> str:
    return f"---\ntype: Note\ntitle: {title}\n---\n# {title}\n"


def _pin(path: Path, **options: Any) -> dict[str, Any]:
    r = read_package(str(path), **options)
    assert r.valid, path
    return {"id": r.manifest["id"], "version": "1.0.0", "digest": r.digest}


def test_a_diamond_of_shared_members_reads_each_member_once(tmp_path: Path) -> None:
    n = 45
    pkgs = tmp_path / "pkgs"
    leaves = []
    for i in range(n):
        files = {"content/a.md": _node(f"Leaf {i}")}
        if i == 0:
            files["sources/big.txt"] = "x" * (2 * 1024 * 1024)  # read 2,025 times without sharing
        _pkg(pkgs / f"leaf-{i}", {"id": f"{ID}/leaf-{i}", "title": f"Leaf {i}"}, files)
        leaves.append(_pin(pkgs / f"leaf-{i}"))
    mids = []
    for i in range(n):
        _pkg(pkgs / f"mid-{i}", {"id": f"{ID}/mid-{i}", "title": f"Mid {i}", "members": leaves})
        mids.append(_pin(pkgs / f"mid-{i}", resolve_member=directory_resolver([pkgs])))
    top = tmp_path / "top"
    _pkg(top, {"id": f"{ID}/top", "title": "Top", "members": mids})

    resolver = directory_resolver([pkgs])
    calls = 0

    def counting(member: dict[str, Any]) -> str | None:
        nonlocal calls
        calls += 1
        return resolver(member)

    tracemalloc.start()
    started = time.perf_counter()
    r = read_package(str(top), resolve_member=counting)
    seconds = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert r.valid
    assert calls == 2 * n, "each distinct member is resolved once"
    assert all(m.status == "resolved" for m in r.members)
    assert r.members[0].result is not None
    assert all(m.status == "resolved" for m in r.members[0].result.members), "a shared member resolves everywhere"
    assert seconds < 30, f"read in {seconds:.1f} s"
    assert peak < 512 * 1024 * 1024, f"peak {peak // 1048576} MiB"

    # The byte budget: past it, no further member is resolved (R001).
    capped = read_package(str(top), resolve_member=resolver, limits={"maxMemberBytes": 1024 * 1024})
    assert any(d.code == "R001_MEMBER_UNRESOLVED" and "bytes" in d.message for d in capped.diagnostics)


def test_a_long_reading_order_over_a_shared_subtree_resolves_in_linear_time(tmp_path: Path) -> None:
    n = 3000
    lines = ["@prefix skos: <http://www.w3.org/2004/02/skos/core#> .", "@prefix dcterms: <http://purl.org/dc/terms/> ."]
    members = " ".join(f"<{ID}/order#m{i}>" for i in range(n))
    lines.append(f"<{ID}/order#list> a skos:OrderedCollection ; skos:memberList ( {members} ) .")
    lines += [f"<{ID}/order#m{i}> a skos:Concept ; dcterms:hasPart <{ID}/order#c0> ." for i in range(n)]
    lines += [
        f"<{ID}/order#c{i}> a skos:Concept" + (f" ; dcterms:hasPart <{ID}/order#c{i + 1}>" if i + 1 < n else "") + " ."
        for i in range(n)
    ]
    _pkg(
        tmp_path,
        {"id": f"{ID}/order", "title": "Order", "readingOrder": f"{ID}/order#list"},
        {"content/a.md": _node("A"), "structure.ttl": "\n".join(lines) + "\n"},
    )

    started = time.perf_counter()
    r = read_package(str(tmp_path))
    seconds = time.perf_counter() - started
    assert r.valid
    positions = package_state(r)["readingOrder"]["positions"]
    assert positions[f"{ID}/order#c{n - 1}"] == 0, "the first member that reaches a concept places it"
    assert positions[f"{ID}/order#m{n - 1}"] == n - 1
    assert seconds < 15, f"read in {seconds:.1f} s"


def test_bindings_by_composition_stay_linear_in_work_and_state_size(tmp_path: Path) -> None:
    n = 2000
    member = tmp_path / "pkgs" / "member"
    _pkg(member, {"id": f"{ID}/member", "title": "Member"}, {f"content/n{i}.md": _node(f"Node {i}") for i in range(n)})
    pin = _pin(member)

    # Every node is bound, under a chain of n concepts: n squared ancestors if each node's were listed.
    lines = ["@prefix skos: <http://www.w3.org/2004/02/skos/core#> ."]
    lines += [
        f"<{ID}/composer#c{i}> a skos:Concept" + (f" ; skos:broader <{ID}/composer#c{i - 1}>" if i > 0 else "") + " ."
        for i in range(n)
    ]
    lines += [f"<{ID}/member#n{i}.md> a skos:Concept ; skos:broader <{ID}/composer#c{n - 1}> ." for i in range(n)]
    composer = tmp_path / "composer"
    _pkg(composer, {"id": f"{ID}/composer", "title": "Composer", "members": [pin]}, {"structure.ttl": "\n".join(lines)})

    tracemalloc.start()
    started = time.perf_counter()
    r = read_package(str(composer), resolve_member=directory_resolver([tmp_path / "pkgs"]))
    assert r.valid
    size = len(json.dumps(package_state(r)))
    library = Library().add(r)
    records = Search(library, LexicalBackend(library)).search("node", scope=f"{ID}/composer#c0", limit=100)
    listed = library.structure.nodes(f"{ID}/composer#c0")
    seconds = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(records) == 100, "search under the top of the chain finds bound nodes"
    assert len(listed) == n, "nodes() lists every bound node under the top of the chain"
    assert size < 1024 * 1024, f"package state is {size} bytes"
    assert seconds < 60, f"read and searched in {seconds:.1f} s"
    assert peak < 512 * 1024 * 1024, f"peak {peak // 1048576} MiB"


def test_a_refined_quote_over_a_4_mib_transcript_is_located_in_linear_time() -> None:
    from moca_reader.evidence_text import Cue, locate_quote

    # 4,096 cues of 1 KiB each: "a a a ...". Quadratic searches took minutes here.
    text = "a " * 512
    cues = [Cue(float(i), float(i + 1), text) for i in range(4096)]
    for exact in ["a", ("a " * 4096).strip()]:
        started = time.perf_counter()
        located = locate_quote(cues, (0.0, 4096.0), {"type": "TextQuoteSelector", "exact": exact})
        seconds = time.perf_counter() - started
        assert located is not None, f"quote of {len(exact)} characters found"
        assert seconds < 60, f"{len(exact)}-character quote located in {seconds:.1f} s"


def test_a_repeat_of_a_member_id_is_not_resolved(tmp_path: Path) -> None:
    leaf = tmp_path / "pkgs" / "leaf"
    _pkg(leaf, {"id": f"{ID}/leaf", "title": "Leaf"}, {"content/a.md": _node("Leaf")})
    pin = _pin(leaf)
    fakes = [{**pin, "digest": "sha256:" + str(i).rjust(64, "0")} for i in range(20)]
    top = tmp_path / "top"
    _pkg(top, {"id": f"{ID}/top", "title": "Top", "members": [pin, *fakes]})
    resolver = directory_resolver([tmp_path / "pkgs"])
    calls = 0

    def counting(member: dict[str, Any]) -> str | None:
        nonlocal calls
        calls += 1
        return resolver(member)

    r = read_package(str(top), resolve_member=counting)
    assert any(d.code == "M005_DUPLICATE_MEMBER" for d in r.diagnostics)
    assert calls == 1, "only the first entry for the id is resolved"
