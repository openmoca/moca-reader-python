"""Damaged archives are reported, never raised (contract §3). Found by fuzzing (fuzz/open_search.py)."""

from __future__ import annotations

import io
import json
import struct
import zipfile

from moca_reader import read_package

MANIFEST = {"mocaVersion": "0.6", "id": "urn:example:damaged", "version": "1.0.0", "title": "Damaged"}


def _archive() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("content/n.md", "---\ntitle: A note\n---\n\nA note.\n")
        z.writestr("moca.json", json.dumps(MANIFEST))
    return buf.getvalue()


def _codes(data: bytes) -> list[str]:
    result = read_package(data)
    assert not result.valid
    return [d.code for d in result.diagnostics]


def test_central_directory_offset_past_its_real_place_is_unreadable_not_raised() -> None:
    # Moving the end record's central-directory offset forward shifts every local header before the start of the
    # file: zipfile then raises ValueError ("negative seek value") on read.
    data = bytearray(_archive())
    eocd = data.rindex(b"PK\x05\x06")
    (offset,) = struct.unpack_from("<I", data, eocd + 16)
    struct.pack_into("<I", data, eocd + 16, offset + 62)
    assert "P002_UNREADABLE_ENTRY" in _codes(bytes(data))


def test_encrypted_entry_is_unreadable_not_raised() -> None:
    # The encryption flag in a central directory header: zipfile raises RuntimeError without a password.
    data = bytearray(_archive())
    central = data.index(b"PK\x01\x02")
    (flags,) = struct.unpack_from("<H", data, central + 8)
    struct.pack_into("<H", data, central + 8, flags | 0x1)
    assert "P002_UNREADABLE_ENTRY" in _codes(bytes(data))


def test_entry_needing_a_newer_zip_version_rejects_the_archive_not_raised() -> None:
    # "Version needed to extract" above what zipfile reads (6.3): zipfile raises NotImplementedError on opening.
    data = bytearray(_archive())
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, central + 6, 236)
    assert _codes(bytes(data)) == ["T003_ARCHIVE_REJECTED"]
