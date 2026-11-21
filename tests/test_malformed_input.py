"""A malformed package never raises out of read_package or bind_sidecar: it is reported (Reader contract §3, §11)."""

from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from moca_reader import Library, bind_sidecar, read_package
from moca_reader._js import MAX_NESTING, json_loads, parse_date
from moca_reader.evidence_text import html_text
from moca_reader.frontmatter import split_frontmatter
from moca_reader.source import _read_checking_each_step, directory_source

NODE = "---\ntype: Note\ntitle: A\n---\n\n# A\n\nText.\n"
MANIFEST = {"id": "https://example.com/m", "version": "1.0.0", "title": "M"}


def package(root: Path, files: dict[str, str | bytes]) -> str:
    for path, data in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(data.encode() if isinstance(data, str) else data)
    return str(root)


def codes(target: str, **options: object) -> list[str]:
    return [d.code for d in read_package(target, **options).diagnostics]  # type: ignore[arg-type]


def deep(levels: int) -> str:
    return "[" * levels + "]" * levels


def test_json_nesting_is_bounded() -> None:
    assert MAX_NESTING == 64
    assert json_loads(deep(MAX_NESTING)) is not None
    # The outermost object is level 1: 63 arrays inside it are 64 levels.
    assert json_loads('{"a": ' + deep(63) + "}") == {"a": json_loads(deep(63))}
    with pytest.raises(ValueError, match="nested more than"):
        json_loads('{"a": ' + deep(64) + "}")
    with pytest.raises(ValueError, match="nested more than"):
        json_loads(deep(MAX_NESTING + 1))
    # Brackets inside strings are text.
    assert json_loads(json.dumps({"a": "[" * 1000})) == {"a": "[" * 1000}


def test_deep_json_in_a_manifest_or_an_attestation_is_reported(tmp_path: Path) -> None:
    manifest = json.dumps(MANIFEST)[:-1] + f', "x": {deep(5000)}}}'
    assert codes(package(tmp_path / "m", {"moca.json": manifest, "content/a.md": NODE})) == [
        "M001_MANIFEST_INVALID_JSON"
    ]
    attestation = {"moca.json": json.dumps(MANIFEST), "content/a.md": NODE, "attestations/a.dsse.json": deep(5000)}
    assert codes(package(tmp_path / "a", attestation)) == ["A001_ATTESTATION_MALFORMED"]


def test_deep_frontmatter_is_c002(tmp_path: Path) -> None:
    # The top mapping is level 1: 63 flow sequences inside it are 64 levels; one more is refused.
    assert split_frontmatter(f"---\na: {deep(MAX_NESTING - 1)}\n---\n").error is None
    assert "nested more than 64" in (split_frontmatter(f"---\na: {deep(MAX_NESTING)}\n---\n").error or "")
    block = "".join(f"{'  ' * i}k{i}:\n" for i in range(MAX_NESTING - 1)) + f"{'  ' * (MAX_NESTING - 1)}k: v\n"
    assert split_frontmatter(f"---\n{block}---\n").error is None
    assert "nested more than" in (split_frontmatter(f"---\na: {deep(2000)}\n---\n").error or "")
    node = f"---\ntype: Note\nx: {deep(2000)}\n---\n\nText.\n"
    assert "C002_FRONTMATTER_INVALID" in codes(
        package(tmp_path / "p", {"moca.json": json.dumps(MANIFEST), "content/a.md": node})
    )


def zip_bytes(entries: dict[str, str]) -> bytearray:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for name, text in entries.items():
            zf.writestr(name, text)
    return bytearray(out.getvalue())


def test_an_encrypted_zip_entry_is_unreadable(tmp_path: Path) -> None:
    data = zip_bytes({"moca.json": json.dumps(MANIFEST), "content/a.md": NODE})
    # Set the encryption flag in each local header and directory entry.
    for signature, flags_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = data.find(signature)
        while at != -1:
            data[at + flags_at] |= 1
            at = data.find(signature, at + 4)
    path = tmp_path / "p.moca"
    path.write_bytes(bytes(data))
    assert set(codes(str(path))) == {"P002_UNREADABLE_ENTRY"}


def test_a_member_whose_manifest_is_not_an_object_is_not_resolved(tmp_path: Path) -> None:
    member = package(tmp_path / "member", {"moca.json": "[]", "content/a.md": NODE})
    pin = {"id": "https://example.com/member", "version": "1.0.0", "digest": "sha256:" + "0" * 64}
    composite = package(tmp_path / "c", {"moca.json": json.dumps({**MANIFEST, "members": [pin]})})
    result = read_package(composite, resolve_member=lambda m: member)
    assert result.members[0].status == "mismatch"
    assert "R002_MEMBER_DIGEST_MISMATCH" in [d.code for d in result.diagnostics]


def test_numeric_entities_of_any_length() -> None:
    assert html_text("&#65;&#x41;&#0000065;") == "AAA"
    long = "&#" + "9" * 5000 + ";"
    assert html_text(long) == long
    assert html_text("&#x" + "f" * 5000 + ";").startswith("&#x")


@pytest.mark.parametrize(
    ("value", "edge"),
    [("0001-01-01T00:30:00+01:00", datetime.min), ("9999-12-31T23:30:00-01:00", datetime.max)],
)
def test_dates_at_the_ends_of_the_calendar(value: str, edge: datetime) -> None:
    assert parse_date(value) == edge.replace(tzinfo=UTC)


def test_a_window_at_the_ends_of_the_calendar_is_read(tmp_path: Path) -> None:
    manifest = {**MANIFEST, "validFrom": "0001-01-01T00:00:00+01:00", "validUntil": "9999-12-31T23:00:00-02:00"}
    result = read_package(package(tmp_path / "p", {"moca.json": json.dumps(manifest), "content/a.md": NODE}))
    assert result.valid
    assert Library().add(result).citations()[0]["trust"]["inForce"] is True


def test_a_sidecar_with_an_unreadable_entry_is_s001(tmp_path: Path) -> None:
    pkg = read_package(package(tmp_path / "p", {"moca.json": json.dumps(MANIFEST), "content/a.md": NODE}))
    data = zip_bytes({"index.json": "{}"})
    data[data.find(b"{}")] = ord("[")  # the stored bytes no longer match their CRC-32
    path = tmp_path / "s.zip"
    path.write_bytes(bytes(data))
    bound = bind_sidecar(str(path), pkg)
    assert not bound.usable
    assert [d.code for d in bound.diagnostics] == ["S001_SIDECAR_INVALID"]
    assert "could not be read" in bound.diagnostics[0].message


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="needs POSIX symbolic links")
def test_a_directory_source_never_follows_a_link_swapped_in_after_listing(tmp_path: Path) -> None:
    root = Path(package(tmp_path / "p", {"moca.json": json.dumps(MANIFEST), "content/a.md": NODE}))
    elsewhere = Path(package(tmp_path / "elsewhere", {"a.md": "host file"}))
    source = directory_source(root)
    assert [e.path for e in source.list()] == ["content/a.md", "moca.json"]
    assert source.read("content/a.md") == NODE.encode()
    # The parent directory is replaced by a link after listing.
    (root / "content" / "a.md").unlink()
    (root / "content").rmdir()
    (root / "content").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(OSError):
        source.read("content/a.md")
    # And the file itself.
    (root / "content").unlink()
    (root / "content").mkdir()
    (root / "content" / "a.md").symlink_to(elsewhere / "a.md")
    with pytest.raises(OSError):
        source.read("content/a.md")


@pytest.mark.parametrize(
    "value", ["!!python/object:os.system x", "!custom 1", "!!timestamp 2026-01-01", "!!set {a}", "!thing [1]"]
)
def test_frontmatter_refuses_tags_outside_the_core_schema(value: str) -> None:
    assert "is not allowed" in (split_frontmatter(f"---\na: {value}\n---\n").error or "")


def test_frontmatter_reads_core_tags() -> None:
    split = split_frontmatter("---\na: !!str 5\nb: !!seq [1]\nc: !!map {d: 1}\ne: ! x\n---\n")
    assert split.error is None
    assert split.data == {"a": "5", "b": [1], "c": {"d": 1}, "e": "x"}


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="needs POSIX symbolic links")
def test_the_step_by_step_check_used_on_windows_refuses_links(tmp_path: Path) -> None:
    root = Path(package(tmp_path / "p", {"content/a.md": NODE}))
    elsewhere = Path(package(tmp_path / "elsewhere", {"a.md": "host file"}))
    assert _read_checking_each_step(str(root), ["content", "a.md"], 1 << 20) == NODE.encode()
    (root / "content" / "a.md").unlink()
    (root / "content").rmdir()
    (root / "content").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(OSError, match="symbolic link"):
        _read_checking_each_step(str(root), ["content", "a.md"], 1 << 20)
