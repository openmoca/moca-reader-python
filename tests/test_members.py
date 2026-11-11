"""Composition limits (package spec §7.1, Reader contract §3)."""

from __future__ import annotations

import json
from pathlib import Path

from moca_reader import read_package

NODE = "---\ntype: Note\ntitle: A\n---\n\n# A\n\nText about refunds.\n"


def make_package(root: Path, manifest: dict[str, object], files: dict[str, str]) -> str:
    root.mkdir(parents=True)
    (root / "moca.json").write_text(json.dumps(manifest))
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    return str(root)


def test_members_past_the_depth_or_count_limit_are_not_resolved(tmp_path: Path) -> None:
    leaves = [
        make_package(
            tmp_path / f"leaf{n}",
            {"id": f"https://example.com/leaf{n}", "version": "1.0.0", "title": "L"},
            {"content/a.md": NODE},
        )
        for n in (1, 2)
    ]
    pins = [
        {"id": f"https://example.com/leaf{n}", "version": "1.0.0", "digest": read_package(leaf).digest}
        for n, leaf in zip((1, 2), leaves, strict=True)
    ]
    composite = make_package(
        tmp_path / "c", {"id": "https://example.com/c", "version": "1.0.0", "title": "C", "members": pins}, {}
    )

    def resolve(m: dict[str, str]) -> str:
        return leaves[int(m["id"][-1]) - 1]

    ok = read_package(composite, resolve_member=resolve)
    assert [m.status for m in ok.members] == ["resolved", "resolved"]

    shallow = read_package(composite, resolve_member=resolve, limits={"maxMemberDepth": 0})
    assert [d.code for d in shallow.diagnostics] == ["R001_MEMBER_UNRESOLVED", "R001_MEMBER_UNRESOLVED"]
    assert "deeper than 0 levels" in shallow.diagnostics[0].message

    few = read_package(composite, resolve_member=resolve, limits={"maxMembers": 1})
    assert [m.status for m in few.members] == ["resolved", "unresolved"]
    assert any("more than 1 members" in d.message for d in few.diagnostics)
