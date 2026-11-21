"""Manifest checks beyond the JSON Schema (package spec §4)."""

from __future__ import annotations

import copy
import re
import unicodedata
from collections.abc import Iterable, Mapping
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
    "url",
    "contributors",
    "datePublished",
    "datePackaged",
    "distribution",
    "images",
    "translations",
    "tags",
    "apps",
    "readingOrder",
    "issuedCopies",
    "terms",
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
    unrecognised = False
    for uri in profiles if isinstance(profiles, dict) else []:
        if uri not in known:
            unrecognised = True
            diagnostics.add(
                "F001_PROFILE_UNRECOGNISED",
                f"profile {uri} is not recognised; its data is preserved but not interpreted",
                file,
            )
    # Package spec §7.2: a type that is neither core nor defined by a declared profile is reported, unless the
    # package declares a profile this Reader does not recognise, which might define it.
    relations = manifest.get("relations")
    if not unrecognised and isinstance(relations, list):
        defined = {
            t for uri in (profiles if isinstance(profiles, dict) else []) for t in PROFILE_RELATION_TYPES.get(uri, ())
        }
        for r in relations:
            kind = r.get("type") if isinstance(r, dict) else None
            if isinstance(kind, str) and kind not in CORE_RELATION_TYPES and kind not in defined:
                diagnostics.add(
                    "R005_RELATION_TYPE_UNKNOWN",
                    f'relation type "{kind}" is not a core type and no declared profile defines it; '
                    "it is preserved and has no effect",
                    file,
                )


# Package spec §7.2: the core relation types.
CORE_RELATION_TYPES = frozenset({"supersedes", "amends", "conflictsWith", "crossReferences", "isPartOf"})

# Relation types each recognised profile defines. None does yet.
PROFILE_RELATION_TYPES: dict[str, tuple[str, ...]] = {}


# Package spec §4.6: the first bytes of each image type.
_PNG = b"\x89PNG\r\n\x1a\n"


def has_signature(image_type: str, data: bytes) -> bool:
    """Whether bytes start with the signature of an image type. A Reader never decodes an image."""
    if image_type == "image/png":
        return data.startswith(_PNG)
    if image_type == "image/jpeg":
        return data.startswith(b"\xff\xd8\xff")
    if image_type == "image/webp":
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    return False


def image_problem(src: str, image_type: str, data: Mapping[str, bytes], max_image_bytes: int) -> str | None:
    """Package spec §4.6: why an image fails its checks, or None when it passes."""
    content = data.get(unicodedata.normalize("NFC", src))
    if content is None:
        return f"{src} is not a file in the package"
    if len(content) > max_image_bytes:
        return f"{src} is {len(content)} bytes, over the limit of {max_image_bytes}"
    if not has_signature(image_type, content):
        return f"{src} does not start with the signature of {image_type}"
    return None


def checked_credit(
    credit: dict[str, Any],
    where: str,
    data: Mapping[str, bytes],
    max_image_bytes: int,
    diagnostics: Diagnostics,
    file: str,
) -> dict[str, Any]:
    """Package spec §4.13: a credit as written, less an image that fails the check of §4.6 (M010, against ``file``).

    The rest of the credit stands.
    """
    out = copy.deepcopy(credit)
    image = out.get("image")
    if isinstance(image, dict):
        problem = image_problem(image["src"], image["type"], data, max_image_bytes)
        if problem:
            diagnostics.add("M010_IMAGE_INVALID", f"{where}.image: {problem}; the image is left out", file)
            del out["image"]
    return out


def _fold_ascii(s: str) -> str:
    """Package spec §2: case-insensitive means A-Z and a-z only."""
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def _dedupe_tags(tags: list[str], where: str, diagnostics: Diagnostics) -> list[str]:
    """Package spec §4.8: a tag list without case-insensitive repeats; each repeat is M012."""
    seen: set[str] = set()
    out: list[str] = []
    for tag in tags:
        key = _fold_ascii(tag)
        if key in seen:
            diagnostics.add(
                "M012_TAG_DUPLICATE", f'{where} repeats the tag "{tag}"; the repeat is dropped', "moca.json"
            )
            continue
        seen.add(key)
        out.append(tag)
    return out


def check_catalogue(
    manifest: dict[str, Any], data: Mapping[str, bytes], diagnostics: Diagnostics, max_image_bytes: int
) -> dict[str, Any]:
    """Package spec §4.6-4.8, §4.13: images, translations, tags and credits, once the manifest passes its schema.

    Returns what the result exposes: ``images``, ``translations``, ``tags``, ``publisher``, ``url`` and
    ``contributors``, each only when declared.
    """
    file = "moca.json"
    out: dict[str, Any] = {}
    declared: set[str] = set()
    dropped: set[str] = set()
    if "images" in manifest:
        out["images"] = []
        for image in manifest["images"]:
            declared.add(image["src"])
            problem = image_problem(image["src"], image["type"], data, max_image_bytes)
            if problem:
                diagnostics.add("M010_IMAGE_INVALID", f"{problem}; the image is left out", file)
                dropped.add(image["src"])
                continue
            out["images"].append(dict(image))
    if "tags" in manifest:
        out["tags"] = _dedupe_tags(manifest["tags"], "tags", diagnostics)
    # Package spec §4.13: credits, exposed as written; labels, not proof.
    if "publisher" in manifest:
        out["publisher"] = checked_credit(manifest["publisher"], "publisher", data, max_image_bytes, diagnostics, file)
    if "url" in manifest:
        out["url"] = manifest["url"]
    if "contributors" in manifest:
        out["contributors"] = [
            checked_credit(c, f"contributors[{i}]", data, max_image_bytes, diagnostics, file)
            for i, c in enumerate(manifest["contributors"])
        ]
    if "translations" in manifest:
        locales = {_fold_ascii(t) for t in manifest.get("locales", [])}
        out["translations"] = {}
        for tag, value in manifest["translations"].items():
            if _fold_ascii(tag) not in locales:
                diagnostics.add(
                    "M011_TRANSLATION_LOCALE_UNDECLARED",
                    f'translations has "{tag}", which is not a tag in locales',
                    file,
                )
            t = dict(value)
            if "tags" in value:
                t["tags"] = _dedupe_tags(value["tags"], f"translations.{tag}.tags", diagnostics)
            if "alt" in value:
                t["alt"] = {}
                for src, text in value["alt"].items():
                    if src not in declared:
                        diagnostics.add(
                            "M013_ALT_IMAGE_UNKNOWN",
                            f"translations.{tag}.alt names {src}, which is not in images; it is dropped",
                            file,
                        )
                        continue
                    # An image dropped with M010 takes its alt text with it, without a further diagnostic.
                    if src not in dropped:
                        t["alt"][src] = text
            out["translations"][tag] = t
    return out
