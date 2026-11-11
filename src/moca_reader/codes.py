"""Diagnostic codes. This table mirrors Reader contract §11, which is normative: codes are the contract,
message prose is not. A change here without the matching spec change is a bug."""

from __future__ import annotations

ERROR = "error"
WARNING = "warning"
INFO = "info"

CODES: dict[str, tuple[str, str]] = {
    "T001_TARGET_NOT_FOUND": (ERROR, "The target does not exist."),
    "T002_MANIFEST_NOT_FOUND": (ERROR, "The target exists but has no moca.json at its root."),
    "T003_ARCHIVE_REJECTED": (ERROR, "An archive or host source broke a safety rule or limit."),
    "P001_UNSUPPORTED_ENTRY": (ERROR, "The package contains a symbolic link or other non-regular file."),
    "P002_UNREADABLE_ENTRY": (ERROR, "A package entry could not be read."),
    "P003_PATH_COLLISION": (ERROR, "Two package paths are equal after Unicode NFC normalisation or case folding."),
    "M001_MANIFEST_INVALID_JSON": (ERROR, "moca.json is not valid UTF-8 JSON."),
    "M002_MANIFEST_SCHEMA": (ERROR, "moca.json does not validate against the manifest schema."),
    "M003_NO_CONTENT": (ERROR, "The package has neither a content node nor a member."),
    "M004_UNKNOWN_KEY": (
        INFO,
        "A top-level manifest key is neither defined by the spec nor a vendor x-<vendor>-<key> key.",
    ),
    "M005_DUPLICATE_MEMBER": (ERROR, "The same member id appears more than once."),
    "M006_VALIDITY_WINDOW_INVALID": (WARNING, "validUntil is not later than validFrom."),
    "M007_UNREGISTERED_URN": (INFO, "The package id uses a URN namespace that is not registered with IANA."),
    "M008_DIGEST_V1_PACKAGE": (
        INFO,
        "The package was written for a mocaVersion before 0.4; digests, pins and attestations made then will not match moca-digest-v2.",
    ),
    "M009_MOCA_VERSION_NEWER": (
        WARNING,
        "The package was written for a newer mocaVersion than this Reader implements; it is read on a best-effort basis.",
    ),
    "C001_FRONTMATTER_MISSING": (ERROR, "A concept document has no YAML frontmatter (OKF MUST)."),
    "C002_FRONTMATTER_INVALID": (ERROR, "Frontmatter is not parseable YAML or is not a mapping."),
    "C003_TYPE_MISSING": (ERROR, "Frontmatter has no non-empty type (OKF MUST)."),
    "C004_RESERVED_FILE_INVALID": (ERROR, "index.md or log.md breaks the OKF reserved-file rules."),
    "C005_FIELD_INVALID": (WARNING, "A frontmatter field does not match the node schema."),
    "C006_EVIDENCE_SOURCE_UNKNOWN": (WARNING, "moca.evidence names a source id that sources[] does not declare."),
    "C007_LINK_UNRESOLVED": (WARNING, "An internal Markdown link does not resolve."),
    "C008_UNSAFE_PATH": (ERROR, "A package-relative path is absolute or escapes the package root."),
    "C009_LOCALE_ORPHAN": (WARNING, "A locale variant has no default-language file."),
    "C010_VALIDITY_WINDOW_INVALID": (WARNING, "moca.valid_until is not later than moca.valid_from."),
    "C011_EVIDENCE_SELECTOR_UNMATCHED": (
        WARNING,
        "An evidence selector does not match the text source file it cites inside the package.",
    ),
    "A001_ATTESTATION_MALFORMED": (ERROR, "An attestation file is not a parseable envelope and statement."),
    "A002_ATTESTATION_INVALID": (ERROR, "An attestation failed verification or does not match the package."),
    "A003_ATTESTATION_UNVERIFIABLE": (
        WARNING,
        "An attestation could not be checked because no trust root was supplied.",
    ),
    "A004_ATTESTATION_INDETERMINATE": (WARNING, "Online verification was requested but could not complete."),
    "A006_REVIEW_OUTDATED": (
        WARNING,
        "A review attestation covers a file whose bytes have since changed or been removed.",
    ),
    "A007_REVIEW_DATE_FUTURE": (WARNING, "A review is dated later than the host clock, so it does not count."),
    "A008_PACKAGE_DIGEST_MISMATCH": (
        ERROR,
        "A package attestation names this id and version with a different digest: the content changed after it was signed.",
    ),
    "A009_SIGNATURE_REQUIRED": (ERROR, "The host requires a valid package attestation and the package has none."),
    "R001_MEMBER_UNRESOLVED": (WARNING, "A member could not be resolved by the host resolver."),
    "R002_MEMBER_DIGEST_MISMATCH": (ERROR, "A resolved member does not match its pinned digest."),
    "R003_MEMBER_CYCLE": (ERROR, "Members form a cycle."),
    "L001_IDENTITY_CONFLICT": (
        ERROR,
        "A library was given a second package with the same id and version but a different digest; the second is refused.",
    ),
    "R004_RELATION_UNAUTHORISED": (
        INFO,
        "A supersedes or conflictsWith relation is not authorised by a signer of the package, so it has no effect.",
    ),
    "F001_PROFILE_UNRECOGNISED": (INFO, "A declared profile is not recognised by this reader."),
    "O001_ONTOLOGY_UNPARSEABLE": (
        WARNING,
        "A structure or overlay file is over the size or triple limit, or is not parseable Turtle.",
    ),
    "O002_CONCEPT_UNDECLARED": (
        WARNING,
        "A concept is used in a relation or node binding but not declared as a skos:Concept.",
    ),
    "O003_REMOTE_REFERENCE": (
        WARNING,
        "An ontology file or concept binding relies on something a Reader would have to fetch or resolve.",
    ),
    "O005_STRUCTURE_CYCLE": (WARNING, "requires, broader or hasPart forms a cycle."),
    "S001_SIDECAR_INVALID": (ERROR, "index.json does not validate against the sidecar schema."),
    "S002_SIDECAR_TARGET_MISMATCH": (ERROR, "The sidecar is bound to a different package id or version."),
    "S003_SIDECAR_STALE": (WARNING, "The sidecar digest does not match the package; the sidecar is ignored."),
    "S004_SIDECAR_ITEM_INVALID": (ERROR, "A payload item breaks the addressing rules."),
    "S005_SIDECAR_FORMAT_UNKNOWN": (INFO, "The payload format is not recognised; the sidecar is ignored."),
    "S006_MODEL_MISMATCH": (WARNING, "The host's embedder does not match the index's model; dense search is refused."),
    "S007_NO_VECTORS": (
        WARNING,
        "A loaded package has no vectors a dense backend can search; that package is not searched.",
    ),
}

# Codes that are no longer emitted. Codes are never reused.
RETIRED_CODES = ("A005_SKILLS_WITHHELD", "K001_SKILL_INVALID", "O004_STRUCTURE_VIEW_MISMATCH")


def default_severity(code: str) -> str:
    if code not in CODES:
        raise KeyError(f"unknown diagnostic code {code}")
    return CODES[code][0]
