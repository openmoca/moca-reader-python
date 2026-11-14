"""Package spec §4.6-4.8: images, translations and tags. The corpus covers the codes; these cover what it cannot.

The same tests as moca-reader-typescript's test/catalogue.test.js.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from moca_reader import read_package

NODE = "---\ntype: Note\ntitle: A\n---\n\n# A\n\nText.\n"
PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452")
JPEG = bytes.fromhex("ffd8ffe000104a464946")
WEBP = b"RIFF" + bytes(4) + b"WEBPVP8L"


def make_package(root: Path, manifest: dict[str, Any], files: dict[str, bytes] | None = None) -> Path:
    full = {"id": "https://example.com/t", "version": "1.0.0", "title": "T", **manifest}
    root.mkdir(parents=True, exist_ok=True)
    (root / "moca.json").write_text(json.dumps(full))
    for path, data in {"content/a.md": NODE.encode(), **(files or {})}.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(data)
    return root


def codes(r: Any) -> list[str]:
    return [d.code for d in r.diagnostics]


def test_each_image_type_is_checked_by_its_own_signature_only(tmp_path: Path) -> None:
    images = [
        {"src": "media/a.png", "role": "icon", "type": "image/png"},
        {"src": "media/a.jpg", "role": "cover", "type": "image/jpeg"},
        {"src": "media/a.webp", "role": "cover", "type": "image/webp"},
        {"src": "media/b.webp", "role": "cover", "type": "image/webp"},
    ]
    files = {"media/a.png": PNG, "media/a.jpg": JPEG, "media/a.webp": WEBP, "media/b.webp": PNG}
    r = read_package(make_package(tmp_path, {"images": images}, files))
    assert codes(r) == ["M010_IMAGE_INVALID"]
    assert [i["src"] for i in r.images or []] == ["media/a.png", "media/a.jpg", "media/a.webp"]


def test_an_image_at_the_limit_passes_and_one_byte_over_does_not(tmp_path: Path) -> None:
    pkg = make_package(
        tmp_path, {"images": [{"src": "media/a.png", "role": "icon", "type": "image/png"}]}, {"media/a.png": PNG}
    )
    assert codes(read_package(pkg, limits={"maxImageBytes": len(PNG)})) == []
    assert codes(read_package(pkg, limits={"maxImageBytes": len(PNG) - 1})) == ["M010_IMAGE_INVALID"]


def test_an_image_under_a_hidden_directory_is_missing(tmp_path: Path) -> None:
    image = {"src": "media/.hidden/a.png", "role": "icon", "type": "image/png"}
    r = read_package(make_package(tmp_path, {"images": [image]}, {"media/.hidden/a.png": PNG}))
    assert codes(r) == ["M010_IMAGE_INVALID"]


def test_the_fields_are_none_when_absent_and_when_the_package_is_invalid(tmp_path: Path) -> None:
    none = read_package(make_package(tmp_path / "a", {}))
    assert (none.images, none.translations, none.tags) == (None, None, None)
    invalid = read_package(make_package(tmp_path / "b", {"tags": ["a"]}, {"content/b.md": b"no frontmatter\n"}))
    assert not invalid.valid
    assert invalid.tags is None


def test_the_result_never_shares_objects_with_the_manifest(tmp_path: Path) -> None:
    image = {"src": "media/a.png", "role": "icon", "type": "image/png"}
    r = read_package(make_package(tmp_path, {"images": [image], "tags": ["a"]}, {"media/a.png": PNG}))
    assert r.images is not None and r.tags is not None
    r.images[0]["src"] = "changed"
    r.tags.append("b")
    assert r.manifest["images"][0]["src"] == "media/a.png"
    assert r.manifest["tags"] == ["a"]
