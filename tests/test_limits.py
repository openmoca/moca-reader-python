"""Bounded work on untrusted input (Reader contract §3, attestations §7): Zip records, attestation files,
signature entries and structure member lists."""

from __future__ import annotations

import base64
import io
import json
import zipfile
from pathlib import Path

import pytest

from moca_reader import read_package
from moca_reader.attestations import PAYLOAD_TYPE, STATEMENT_TYPE, parse_attestation
from moca_reader.dsse import MAX_SIGNATURES, verify_envelope
from moca_reader.source import TargetError, check_archive_records

NODE = "---\ntype: Note\ntitle: A\n---\n\n# A\n\nText.\n"
MANIFEST = {"id": "https://example.com/l", "version": "1.0.0", "title": "L"}


def archive(entries: dict[str, str], comment: bytes = b"") -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for name, text in entries.items():
            zf.writestr(name, text)
        zf.comment = comment
    return out.getvalue()


def rejected(data: bytes) -> str:
    with pytest.raises(TargetError) as err:
        check_archive_records(data)
    assert err.value.code == "T003_ARCHIVE_REJECTED"
    return str(err.value)


def test_a_well_formed_archive_passes() -> None:
    check_archive_records(archive({"moca.json": "{}", "content/a.md": NODE}, comment=b"a comment"))


def test_the_end_record_must_end_the_file_and_be_the_only_one() -> None:
    good = archive({"moca.json": "{}"})
    assert "no end-of-central-directory record" in rejected(good + b"trailing")
    assert "no end-of-central-directory record" in rejected(b"PK")
    # A comment that holds an end record which also ends exactly at the end of the file.
    fake_end = b"PK\x05\x06" + bytes(16) + b"\x00\x00"
    assert "more than one" in rejected(archive({"moca.json": "{}"}, comment=fake_end))


def test_zip64_and_multi_disk_are_refused() -> None:
    data = bytearray(archive({"moca.json": "{}"}))
    end = len(data) - 22
    zip64 = bytearray(data)
    zip64[end + 10 : end + 12] = b"\xff\xff"
    zip64[end + 8 : end + 10] = b"\xff\xff"
    assert "Zip64" in rejected(bytes(zip64))
    disk = bytearray(data)
    disk[end + 4 : end + 6] = b"\x01\x00"
    assert "multi-disk" in rejected(bytes(disk))


def test_a_local_header_must_match_its_directory_entry() -> None:
    data = bytearray(archive({"content/a.md": NODE}))
    data[30:42] = b"content/b.md"  # the local header's name only
    assert "local header does not match" in rejected(bytes(data))


def test_an_archive_read_by_path_is_checked_and_its_file_closed(tmp_path: Path) -> None:
    path = tmp_path / "p.moca"
    path.write_bytes(archive({"moca.json": json.dumps(MANIFEST), "content/a.md": NODE}) + b"x")
    result = read_package(str(path))
    assert [d.code for d in result.diagnostics] == ["T003_ARCHIVE_REJECTED"]


def statement_file(signatures: int) -> bytes:
    statement = {"_type": STATEMENT_TYPE, "subject": [], "predicateType": "https://example.com/p"}
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return json.dumps(
        {"payload": payload, "payloadType": PAYLOAD_TYPE, "signatures": [{"keyid": "k", "sig": "AA=="}] * signatures}
    ).encode()


def test_an_envelope_holds_at_most_16_signatures() -> None:
    assert not isinstance(parse_attestation("attestations/a.dsse.json", statement_file(MAX_SIGNATURES)), str)
    reason = parse_attestation("attestations/a.dsse.json", statement_file(MAX_SIGNATURES + 1))
    assert isinstance(reason, str) and "more than 16" in reason
    many = json.loads(statement_file(MAX_SIGNATURES + 1))
    assert verify_envelope(many, lambda keyid: None).reason == "more than 16 signature entries"


def package_with_attestations(root: Path, count: int, size: int = 0) -> str:
    root.mkdir()
    (root / "moca.json").write_text(json.dumps(MANIFEST))
    (root / "content").mkdir()
    (root / "content" / "a.md").write_text(NODE)
    (root / "attestations").mkdir()
    for i in range(count):
        (root / "attestations" / f"a{i}.dsse.json").write_bytes(statement_file(1) + b" " * size)
    return str(root)


def test_attestation_files_are_bounded_in_number_and_size(tmp_path: Path) -> None:
    many = read_package(package_with_attestations(tmp_path / "many", 3), limits={"maxAttestations": 2})
    assert [d.code for d in many.diagnostics] == ["A001_ATTESTATION_MALFORMED"]
    assert "over the 2 limit; none is read" in many.diagnostics[0].message
    big = read_package(package_with_attestations(tmp_path / "big", 1, 2000), limits={"maxAttestationBytes": 1000})
    assert big.attestations[0]["outcome"] == "malformed"
    assert "1000-byte limit" in big.attestations[0]["reason"]


def test_member_lists_are_walked_once_and_counted_per_collection(tmp_path: Path) -> None:
    root = tmp_path / "p"
    root.mkdir()
    (root / "moca.json").write_text(json.dumps(MANIFEST))
    (root / "content").mkdir()
    (root / "content" / "a.md").write_text(NODE)
    # One list of 50 cells, written out, that 40 collections name: about 190 triples and 2,000 cells.
    cells = "\n".join(
        f"_:l{i} rdf:first ex:c{i} ; rdf:rest {f'_:l{i + 1}' if i < 49 else 'rdf:nil'} ." for i in range(50)
    )
    subjects = "\n".join(f"ex:s{k} a skos:OrderedCollection ; skos:memberList _:l0 ." for k in range(40))
    concepts = "\n".join(f"ex:c{i} a skos:Concept ." for i in range(50))
    (root / "structure.ttl").write_text(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n"
        "@prefix skos: <http://www.w3.org/2004/02/skos/core#> .\n"
        f"@prefix ex: <https://example.com/c/> .\n{concepts}\n{cells}\n{subjects}\n"
    )
    ok = read_package(str(root))
    assert ok.structure is not None and ok.structure.ok
    tight = read_package(str(root), limits={"maxTriples": 1000})
    assert [d.code for d in tight.diagnostics] == ["O001_ONTOLOGY_UNPARSEABLE"]
    assert "collection members" in tight.diagnostics[0].message
