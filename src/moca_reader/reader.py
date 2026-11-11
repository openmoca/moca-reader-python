"""``read_package``: opens a package from any source, checks it, computes its digest, verifies its
attestations against a host trust root, resolves members through a host resolver, and returns everything an
application needs (Reader contract). It never executes package content, never performs network I/O of its
own, and never acts on a location or setting a package supplies.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ._js import get, json_loads, parse_date, truthy
from .attestations import (
    PREDICATE_PACKAGE,
    PREDICATE_REVIEW,
    TrustRoot,
    check_package_statement,
    check_review_statement,
    parse_attestation,
    scope_covers,
    verify_signature,
)
from .content import ContentNode, read_content
from .diagnostics import Diagnostic, Diagnostics
from .digest import ATTESTATIONS_DIR, MANIFEST, compute_digest, package_files
from .manifest import check_manifest
from .profiles import KNOWN_PROFILES
from .reviews import review_status_of
from .source import DEFAULT_LIMITS, PackageSource, TargetError, open_source
from .structure import PackageStructure, read_structure
from .unicode import normalize

# A009 invalidates: it is only raised when the host requires a signature.
_INVALIDATING = re.compile(r"^((T|P|M|C)[0-9]|A009)")
ResolveMember = Callable[[dict[str, Any]], Any]


@dataclass
class Review:
    reviewer: str
    reviewed_at: str
    outcome: str
    signer: str | None
    scope: str | None = None


@dataclass
class Member:
    id: Any
    version: Any
    digest: Any
    status: str = "unresolved"  # unresolved | resolved | mismatch | cycle
    result: PackageResult | None = None


@dataclass
class PackageResult:
    """What a Reader concludes about a package (Reader interface §4)."""

    manifest: Any = None
    digest: str | None = None
    nodes: list[ContentNode] = field(default_factory=list)
    file_digests: dict[str, str] = field(default_factory=dict)
    attestations: list[dict[str, Any]] = field(default_factory=list)
    reviews_by_file: dict[str, list[Review]] = field(default_factory=dict)
    signers: list[str] = field(default_factory=list)
    # Package spec §7.2: the package ids its valid package attestations' signers may speak for.
    relation_scopes: list[str] = field(default_factory=list)
    members: list[Member] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    valid: bool = False
    capabilities: list[str] = field(default_factory=list)
    payload_manifest: str | None = None
    structure: PackageStructure | None = None
    source: PackageSource | None = None

    @property
    def id(self) -> Any:
        return get(self.manifest, "id")

    @property
    def version(self) -> Any:
        return get(self.manifest, "version")


@dataclass
class _Options:
    trust_root: TrustRoot | None
    resolve_member: ResolveMember | None
    strict: bool
    limits: dict[str, int]
    known_profiles: tuple[str, ...]
    now: datetime | None
    require_signature: bool = False


MOCA_VERSION = "0.6"
"""The specification version this Reader implements, ``major.minor`` (package spec §14)."""


def _compare_version(major: str, minor: str, version: str) -> int:
    """Compares a declared major.minor with a version string, numerically, without converting to int."""

    def num(a: str, b: str) -> int:
        x, y = a.lstrip("0") or "0", b.lstrip("0") or "0"
        if len(x) != len(y):
            return -1 if len(x) < len(y) else 1
        return (x > y) - (x < y)

    want_major, want_minor = version.split(".")
    return num(major, want_major) or num(minor, want_minor)


def read_package(
    target: Any,
    *,
    trust_root: str | os.PathLike[str] | dict[str, Any] | TrustRoot | None = None,
    resolve_member: ResolveMember | None = None,
    strict: bool = False,
    limits: dict[str, int] | None = None,
    known_profiles: Iterable[str] | None = None,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
    require_signature: bool = False,
) -> PackageResult:
    """Reads and checks a package: a directory, a .moca/.zip archive, or a host source.

    Never raises for a malformed package: ``result.valid`` is False and ``result.diagnostics`` says why.
    """
    options = _Options(
        TrustRoot.load(trust_root) if trust_root is not None else None,
        resolve_member,
        strict,
        {**DEFAULT_LIMITS, **(limits or {})},
        tuple(known_profiles) if known_profiles is not None else KNOWN_PROFILES,
        clock() if clock is not None else now,
        require_signature,
    )
    return _read(target, options, [], [0])


def _read(target: Any, options: _Options, stack: list[Any], budget: list[int]) -> PackageResult:
    diagnostics = Diagnostics(options.strict)
    result = PackageResult(diagnostics=diagnostics.items)
    try:
        source = open_source(target, options.limits)
        source.list()
    except TargetError as err:
        diagnostics.add(err.code, str(err))
        return result
    result.source = source

    entries_ok, files = package_files(source, diagnostics)
    if MANIFEST not in files:
        diagnostics.add("T002_MANIFEST_NOT_FOUND", "the target has no moca.json at its root")
        return _finish(result, diagnostics)

    data: dict[str, bytes] = {}
    readable = True
    for nfc, stored in files.items():
        try:
            data[nfc] = source.read(stored)
        except TargetError as err:
            # A limit broken while reading rejects the whole source (T003), once.
            diagnostics.add(err.code, str(err))
            return result
        except (OSError, KeyError) as err:
            diagnostics.add("P002_UNREADABLE_ENTRY", f'"{stored}" could not be read: {err}', stored)
            readable = False
    # An entry that cannot be read leaves nothing to check the rest against: stop with P002, as the reference does.
    if not readable:
        return _finish(result, diagnostics)

    try:
        # Contract §11, M001: moca.json is UTF-8; invalid bytes are an error, not replaced.
        manifest = json_loads(data[MANIFEST].decode("utf-8").removeprefix("\ufeff"), unique_keys=True)
    except (ValueError, KeyError) as err:
        diagnostics.add("M001_MANIFEST_INVALID_JSON", f"moca.json is not valid UTF-8 JSON: {err}", MANIFEST)
        return _finish(result, diagnostics)
    result.manifest = manifest
    check_manifest(manifest, diagnostics, options.known_profiles)
    profiles = get(manifest, "profiles")
    result.profiles = list(profiles) if isinstance(profiles, dict) else []
    version = get(manifest, "mocaVersion")
    # Package spec §14: M008 only for a declared mocaVersion below 0.4; M009 for one newer than this Reader's.
    declared = re.fullmatch(r"([0-9]+)\.([0-9]+)", "" if version is None else str(version))
    if declared and _compare_version(declared[1], declared[2], "0.4") < 0:
        diagnostics.add(
            "M008_DIGEST_V1_PACKAGE",
            f"written for mocaVersion {version}; its digest is now computed with moca-digest-v2, so pins "
            "and attestations made under 0.3 or earlier will not match",
            MANIFEST,
        )
    if declared and _compare_version(declared[1], declared[2], MOCA_VERSION) > 0:
        diagnostics.add(
            "M009_MOCA_VERSION_NEWER",
            f"written for mocaVersion {version}, newer than {MOCA_VERSION}; read on a best-effort basis",
            MANIFEST,
        )

    if entries_ok and readable:
        digest, file_digests, payload_manifest = compute_digest(files, lambda stored: data[normalize("NFC", stored)])
        result.digest, result.file_digests, result.payload_manifest = digest, file_digests, payload_manifest

    result.nodes = read_content(
        manifest if isinstance(manifest, dict) else {}, files, data, result.file_digests, diagnostics, options.limits
    )
    result.structure = read_structure(data, result.nodes, diagnostics, options.limits, result.digest)
    members = get(manifest, "members")
    members = members if isinstance(members, list) else []
    if not result.nodes and not members:
        diagnostics.add(
            "M003_NO_CONTENT", "a package needs at least one content node under content/ or at least one member"
        )

    if result.digest:
        _read_attestations(result, data, options, diagnostics)
    # Attestations §8: a host can require a valid package attestation.
    if options.require_signature and not result.signers:
        diagnostics.add(
            "A009_SIGNATURE_REQUIRED",
            "the host requires a valid package attestation, and this package has none",
            MANIFEST,
        )
    _check_relation_authority(result, diagnostics)
    _resolve_members(result, members, options, stack, diagnostics, budget)
    return _finish(result, diagnostics)


def _read_attestations(
    result: PackageResult, data: dict[str, bytes], options: _Options, diagnostics: Diagnostics
) -> None:
    from ._js import js_sorted

    manifest, digest = result.manifest, result.digest or ""
    attestation_files = js_sorted(
        p for p in data if p.startswith(f"{ATTESTATIONS_DIR}/") and re.search(r"\.(dsse|sigstore)\.json\Z", p)
    )
    for file in attestation_files:
        parsed = parse_attestation(file, data[file])
        if isinstance(parsed, str):
            diagnostics.add("A001_ATTESTATION_MALFORMED", parsed, file)
            result.attestations.append({"file": file, "outcome": "malformed", "reason": parsed})
            continue
        kind = parsed.statement["predicateType"]
        if kind not in (PREDICATE_PACKAGE, PREDICATE_REVIEW):
            result.attestations.append(
                {"file": file, "predicateType": kind, "outcome": "ignored", "reason": "unknown predicate type"}
            )
            continue
        role = "package" if kind == PREDICATE_PACKAGE else "review"
        sig = verify_signature(parsed, options.trust_root, role, options.now)
        record: dict[str, Any] = {
            "file": file,
            "predicateType": kind,
            "role": role,
            "format": parsed.format,
            "outcome": sig.outcome,
            "signer": sig.signer,
            "reason": sig.reason,
        }
        result.attestations.append(record)
        if sig.outcome == "unverifiable":
            diagnostics.add("A003_ATTESTATION_UNVERIFIABLE", f"{role} attestation not checked: {sig.reason}", file)
            continue
        if sig.outcome == "indeterminate":
            diagnostics.add("A004_ATTESTATION_INDETERMINATE", sig.reason or "", file)
            continue
        if sig.outcome == "invalid":
            diagnostics.add(
                "A002_ATTESTATION_INVALID", f"{role} attestation signature did not verify: {sig.reason}", file
            )
            continue

        if role == "package":
            mismatch = check_package_statement(parsed.statement, get(manifest, "id"), get(manifest, "version"), digest)
            if mismatch:
                record["outcome"], record["reason"] = "invalid", mismatch
                # Attestations §3: a statement naming this id@version with another digest is positive evidence that
                # the content changed after signing.
                subjects = parsed.statement.get("subject") or []
                tampered = (
                    len(subjects) == 1
                    and get(subjects[0], "name") == f"{get(manifest, 'id')}@{get(manifest, 'version')}"
                )
                diagnostics.add(
                    "A008_PACKAGE_DIGEST_MISMATCH" if tampered else "A002_ATTESTATION_INVALID",
                    f"package attestation does not match this package: {mismatch}",
                    file,
                )
            elif sig.signer is not None:
                result.signers.append(sig.signer)
                result.relation_scopes.extend(sig.ids)
            continue

        review = check_review_statement(parsed.statement, get(manifest, "id"), result.file_digests)
        if review.error:
            record["outcome"], record["reason"] = "invalid", review.error
            diagnostics.add("A002_ATTESTATION_INVALID", review.error, file)
            continue
        predicate = review.predicate or {}
        # Attestations §4: a key with a `reviewers` list may only sign as those reviewers.
        if sig.reviewers is not None and predicate.get("reviewer") not in sig.reviewers:
            reason = f"the signing key may not sign as reviewer {predicate.get('reviewer')}"
            record["outcome"], record["reason"] = "invalid", reason
            diagnostics.add("A002_ATTESTATION_INVALID", reason, file)
            continue
        # A review dated after the host clock does not count.
        reviewed_at = parse_date(predicate.get("reviewedAt"))
        if reviewed_at is not None and reviewed_at > (options.now or datetime.now(UTC)):
            reason = f"review is dated {predicate.get('reviewedAt')}, later than now"
            record["outcome"], record["reason"] = "ignored", reason
            diagnostics.add("A007_REVIEW_DATE_FUTURE", reason, file)
            continue
        record["current"], record["outdated"] = review.current, review.outdated
        for path in review.outdated:
            diagnostics.add("A006_REVIEW_OUTDATED", f"review of {path} no longer matches the file", file)
        for path in review.current:
            entry = Review(
                predicate["reviewer"],
                predicate["reviewedAt"],
                predicate["outcome"],
                sig.signer,
                predicate.get("scope") if truthy(predicate.get("scope")) else None,
            )
            result.reviews_by_file.setdefault(normalize("NFC", path), []).append(entry)
    # Attestations §4: for each file, the latest review from each signer counts.
    for path, entries in result.reviews_by_file.items():
        latest: dict[str | None, Review] = {}
        for e in entries:
            prev = latest.get(e.signer)
            if prev is None or _instant(e.reviewed_at) >= _instant(prev.reviewed_at):
                latest[e.signer] = e
        result.reviews_by_file[path] = list(latest.values())


def _check_relation_authority(result: PackageResult, diagnostics: Diagnostics) -> None:
    """Package spec §7.2: supersedes and conflictsWith take effect only when a signer may speak for the target."""
    relations = get(result.manifest, "relations")
    for r in relations if isinstance(relations, list) else []:
        if get(r, "type") not in ("supersedes", "conflictsWith") or not isinstance(get(r, "target"), str):
            continue
        if not scope_covers(result.relation_scopes, r["target"]):
            diagnostics.add(
                "R004_RELATION_UNAUTHORISED",
                f"{r['type']} {r['target']} is not authorised by a signer of this package, so it has no effect",
                MANIFEST,
            )


def _resolve_members(
    result: PackageResult,
    members: list[Any],
    options: _Options,
    stack: list[Any],
    diagnostics: Diagnostics,
    budget: list[int],
) -> None:
    max_depth = options.limits["maxMemberDepth"]
    max_members = options.limits["maxMembers"]
    # Cycles are detected by id@version: composing another version of the same package is not a cycle.
    own_key = f"{get(result.manifest, 'id')}@{get(result.manifest, 'version')}"
    for member in members:
        if not truthy(get(member, "id")) or not truthy(get(member, "digest")):
            continue
        entry = Member(member["id"], member.get("version"), member["digest"])
        result.members.append(entry)
        if options.resolve_member is None:
            continue
        member_key = f"{member['id']}@{member.get('version')}"
        if member_key == own_key or member_key in stack:
            chain = " -> ".join(str(x) for x in [*stack, own_key, member_key])
            diagnostics.add("R003_MEMBER_CYCLE", f"members form a cycle: {chain}", MANIFEST)
            entry.status = "cycle"
            continue
        # Package spec §7.1: depth and the members resolved per read are bounded; a member past either limit is not used.
        if len(stack) + 1 > max_depth:
            diagnostics.add(
                "R001_MEMBER_UNRESOLVED",
                f"member {member_key} is not resolved: composition is deeper than {max_depth} levels",
                MANIFEST,
            )
            continue
        if budget[0] >= max_members:
            diagnostics.add(
                "R001_MEMBER_UNRESOLVED",
                f"member {member_key} is not resolved: more than {max_members} members in one read",
                MANIFEST,
            )
            continue
        budget[0] += 1
        target = options.resolve_member({"id": entry.id, "version": entry.version, "digest": entry.digest})
        if not target:
            diagnostics.add(
                "R001_MEMBER_UNRESOLVED", f"member {entry.id}@{entry.version} could not be resolved", MANIFEST
            )
            continue
        child = _read(target, options, [*stack, own_key], budget)
        entry.result = child
        if any(d.code == "R003_MEMBER_CYCLE" for d in child.diagnostics):
            diagnostics.add("R003_MEMBER_CYCLE", f"member {entry.id} is part of a cycle", MANIFEST)
            entry.status = "cycle"
        elif child.manifest and (
            child.manifest.get("id") != entry.id or (entry.version and child.manifest.get("version") != entry.version)
        ):
            # Package spec §7.1: the resolved member must be the package the pin names.
            diagnostics.add(
                "R002_MEMBER_DIGEST_MISMATCH",
                f"member pinned as {entry.id}@{entry.version} resolved to "
                f"{child.manifest.get('id')}@{child.manifest.get('version')}",
                MANIFEST,
            )
            entry.status = "mismatch"
        elif child.digest != entry.digest:
            diagnostics.add(
                "R002_MEMBER_DIGEST_MISMATCH",
                f"member {entry.id}@{entry.version} has digest {child.digest or '(none)'}, but {entry.digest} is pinned",
                MANIFEST,
            )
            entry.status = "mismatch"
        else:
            entry.status = "resolved"


def _instant(value: str) -> float:
    parsed = parse_date(value)
    return parsed.timestamp() if parsed is not None else float("-inf")


def _finish(result: PackageResult, diagnostics: Diagnostics) -> PackageResult:
    result.valid = not any(d.severity == "error" and _INVALIDATING.match(d.code) for d in diagnostics.items)
    if not result.valid:
        return result
    caps = {"core"}
    all_local = True
    reviewed_files = 0
    all_approved = True
    for node in result.nodes:
        for rep in node.representations:
            evidence = get(rep.frontmatter.get("moca"), "evidence")
            if isinstance(evidence, list) and evidence:
                caps.add("located-evidence")
            if any(not c.local for c in rep.evidence_checks):
                all_local = False
            if rep.locale:
                caps.add("localized")
            if rep.file in result.reviews_by_file:
                reviewed_files += 1
                if review_status_of(result.reviews_by_file[rep.file], bool(result.signers)) != "approved":
                    all_approved = False
    if "located-evidence" in caps and all_local:
        caps.add("self-contained-evidence")
    if result.structure is not None and result.structure.ok:
        caps.add("structured")
    if result.members:
        caps.add("composed")
    if result.signers:
        caps.add("signed")
    # Package spec §11 (moca-spec ADR-0017): signed, and every reviewed file approved.
    if "signed" in caps and reviewed_files > 0 and all_approved:
        caps.add("reviewed")
    result.capabilities = sorted(caps)
    return result
