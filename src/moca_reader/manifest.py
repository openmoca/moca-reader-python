"""Manifest checks beyond the JSON Schema (package spec §4)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ._js import get, parse_date, truthy
from .diagnostics import Diagnostics
from .schemas import validate_against

MANIFEST_KEYS = {
    "$schema",
    "mocaVersion",
    "id",
    "version",
    "title",
    "description",
    "language",
    "locales",
    "license",
    "publisher",
    "validFrom",
    "validUntil",
    "members",
    "relations",
    "profiles",
}
# URN namespaces registered with IANA that are commonly used as package ids. Not exhaustive: M007 is informational.
# Package spec §4.2: the IANA formal URN namespaces, as in moca-spec data/urn-namespaces.json (a test keeps
# them equal). Informal namespaces, urn-<number>, are registered too.
REGISTERED_URN_NIDS = frozenset(
    {
        "3gpp",
        "3gpp2",
        "adid",
        "alert",
        "bbf",
        "broadband-forum-org",
        "c2pa",
        "cablelabs",
        "ccsds",
        "cdx",
        "cgi",
        "clei",
        "csa",
        "cta",
        "ddi",
        "dev",
        "dgiwg",
        "dnp",
        "doi",
        "dslforum-org",
        "dvb",
        "ebu",
        "eic",
        "eidr",
        "epc",
        "epcglobal",
        "etsi",
        "eurosystem",
        "example",
        "fdc",
        "fipa",
        "gdr",
        "gdst",
        "geant",
        "globus",
        "gs1",
        "gsma",
        "gvat",
        "hbbtv",
        "ieee",
        "ietf",
        "iptc",
        "isan",
        "isbn",
        "isni",
        "iso",
        "issn",
        "itu",
        "ivis",
        "knx",
        "lei",
        "lex",
        "liberty",
        "mace",
        "mef",
        "meta",
        "mpeg",
        "mrn",
        "nan",
        "nato",
        "nbn",
        "nena",
        "newsml",
        "nfc",
        "nfi",
        "nzl",
        "oasis",
        "ogc",
        "ogf",
        "oid",
        "oipf",
        "oma",
        "onem2m",
        "onf",
        "pin",
        "pno",
        "publicid",
        "pwid",
        "reso",
        "s1000d",
        "said",
        "schac",
        "service",
        "smpte",
        "stalwart",
        "swift",
        "thread",
        "trivore",
        "tva",
        "uci",
        "ucode",
        "uic",
        "uuid",
        "web3d",
        "wfa",
        "wmo",
        "xmlorg",
        "xmpp",
    }
)
_INFORMAL_URN_NID = re.compile(r"urn-[0-9]+")
_VENDOR_KEY = re.compile(r"^x-[a-z0-9]+-[A-Za-z0-9-]+\Z")
_URN = re.compile(r"^urn:([^:]+):", re.IGNORECASE)


def check_manifest(manifest: Any, diagnostics: Diagnostics, known_profiles: Iterable[str] = ()) -> None:
    file = "moca.json"
    for err in validate_against("manifest", manifest):
        diagnostics.add("M002_MANIFEST_SCHEMA", err, file)
    if not isinstance(manifest, dict):
        return

    for key in manifest:
        if key not in MANIFEST_KEYS and not _VENDOR_KEY.match(key):
            diagnostics.add(
                "M004_UNKNOWN_KEY",
                f'"{key}" is not a MOCA manifest key; it is ignored. Vendor keys use x-<vendor>-<key>.',
                file,
            )

    seen: list[Any] = []
    members = manifest.get("members")
    for m in members if isinstance(members, list) else []:
        member_id = get(m, "id")
        if not truthy(member_id):
            continue
        if member_id in seen:
            diagnostics.add("M005_DUPLICATE_MEMBER", f"member {member_id} is listed more than once", file)
        seen.append(member_id)

    start = parse_date(manifest.get("validFrom"))
    until = parse_date(manifest.get("validUntil"))
    if start is not None and until is not None and until <= start:
        diagnostics.add("M006_VALIDITY_WINDOW_INVALID", "validUntil must be later than validFrom", file)

    urn = _URN.match(manifest["id"]) if isinstance(manifest.get("id"), str) else None
    if urn and urn[1].lower() not in REGISTERED_URN_NIDS and not _INFORMAL_URN_NID.fullmatch(urn[1].lower()):
        diagnostics.add(
            "M007_UNREGISTERED_URN",
            f'"urn:{urn[1]}:" is not a registered URN namespace (RFC 8141); prefer an https: or tag: URI',
            file,
        )

    known = set(known_profiles)
    profiles = manifest.get("profiles")
    for uri in profiles if isinstance(profiles, dict) else []:
        if uri not in known:
            diagnostics.add(
                "F001_PROFILE_UNRECOGNISED",
                f"profile {uri} is not recognised; its data is preserved but not interpreted",
                file,
            )
