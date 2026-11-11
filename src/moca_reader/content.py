"""Content traversal: content/ is an Open Knowledge Format (OKF) v0.2 bundle (package spec §5, contract §5)."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

from ._js import decode_uri_component, get, js_sorted, js_trim, posix_dirname, posix_join, truthy, utf16_key
from .diagnostics import Diagnostics
from .evidence_text import check_selector, normalised_text, source_kind
from .frontmatter import split_frontmatter
from .schemas import validate_against
from .unicode import normalize

CONTENT_DIR = "content"
_RESERVED = {"index.md", "log.md"}
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_LINK = re.compile(
    r"!?\[[^\]]*\]\([\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*(<[^>]+>|[^)\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+)(?:[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+(?:\"[^\"]*\"|'[^']*'))?[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*\)"
)
_PATH_REF = re.compile(r"^(\.{1,2}/|/)")
_EVIDENCE_DIRS = ("sources/", "media/")
_LOCALE = re.compile(r"^(.*)\.([A-Za-z]{2,3}(?:-[A-Za-z0-9]{1,8})*)\.md\Z", re.IGNORECASE | re.ASCII | re.DOTALL)


@dataclass
class EvidenceCheck:
    local: bool
    matched: bool | None = None


@dataclass
class Representation:
    locale: str | None  # None = the default language
    file: str  # package-relative path
    frontmatter: dict[str, Any]
    body: str
    body_offset: int  # UTF-8 byte offset of the body in the file
    sha256: str | None
    evidence_checks: list[EvidenceCheck] = field(default_factory=list)
    concepts: list[str] | None = None


@dataclass
class ContentNode:
    path: str  # relative to content/: the default-language file name
    representations: list[Representation]


def read_content(
    manifest: dict[str, Any],
    files: dict[str, str],
    data: dict[str, bytes],
    file_digests: dict[str, str],
    diagnostics: Diagnostics,
    limits: dict[str, int],
) -> list[ContentNode]:
    source_text: dict[str, str] = {}
    # Contract §3: a per-package budget of evidence checks and of source bytes scanned.
    budget: dict[str, Any] = {"checks": 0, "bytes": 0, "prepared": {}}
    declared = manifest.get("locales")
    locales = {str(loc).lower(): loc for loc in (declared if isinstance(declared, list) else [])}
    by_key: dict[str, ContentNode] = {}
    md_files = js_sorted(p for p in files if p.startswith(f"{CONTENT_DIR}/") and p.lower().endswith(".md"))

    for file in md_files:
        rel = file[len(CONTENT_DIR) + 1 :]
        base = posixpath.basename(rel)
        text = data[file].decode("utf-8", errors="replace")

        if base.lower() in _RESERVED:
            _check_reserved(file, rel, base.lower(), text, diagnostics, limits)
            continue

        key, locale = _locale_of(rel, locales)
        split = split_frontmatter(text, limits["maxFrontmatterBytes"])
        if not split.present:
            diagnostics.add(
                "C001_FRONTMATTER_MISSING", "concept documents must open with a YAML frontmatter block", file
            )
            continue
        if split.error:
            diagnostics.add("C002_FRONTMATTER_INVALID", split.error, file, split.line)
            continue
        fm: dict[str, Any] = split.data
        if not isinstance(fm.get("type"), str) or js_trim(fm["type"]) == "":
            diagnostics.add("C003_TYPE_MISSING", 'frontmatter needs a non-empty "type"', file)
            continue
        for err in validate_against("node", fm):
            diagnostics.add("C005_FIELD_INVALID", err, file)
        _check_evidence(file, fm, diagnostics)
        _check_window(file, fm, diagnostics)
        _check_paths(file, fm, split.body, files, diagnostics)
        checks = _verify_evidence(file, fm, files, data, diagnostics, limits, source_text, budget)

        rep = Representation(locale, file, fm, split.body, split.body_offset, file_digests.get(file), checks)
        by_key.setdefault(key, ContentNode(key, [])).representations.append(rep)

    nodes: list[ContentNode] = []
    for node in sorted(by_key.values(), key=lambda n: utf16_key(n.path)):
        node.representations.sort(key=lambda r: (r.locale is not None, utf16_key(r.locale or "")))
        if node.representations[0].locale is not None:
            diagnostics.add(
                "C009_LOCALE_ORPHAN",
                f"locale variant has no default-language file {CONTENT_DIR}/{node.path}",
                node.representations[0].file,
            )
        nodes.append(node)
    return nodes


def _locale_of(rel: str, locales: dict[str, Any]) -> tuple[str, str | None]:
    m = _LOCALE.match(rel)
    if m and m[2].lower() in locales:
        return f"{m[1]}.md", locales[m[2].lower()]
    return rel, None


def _check_reserved(
    file: str, rel: str, base: str, text: str, diagnostics: Diagnostics, limits: dict[str, Any]
) -> None:
    # Contract §3: the frontmatter size limit applies to reserved files too.
    split = split_frontmatter(text, limits["maxFrontmatterBytes"])
    if base == "index.md":
        if not split.present:
            return
        keys = list(split.data) if isinstance(split.data, dict) else []
        root_index = rel.lower() == "index.md"
        if split.error or not root_index or any(k != "okf_version" for k in keys):
            diagnostics.add(
                "C004_RESERVED_FILE_INVALID",
                "the bundle-root index.md may carry only an okf_version frontmatter key"
                if root_index
                else "index.md files carry no frontmatter",
                file,
            )
        return
    if split.present:
        diagnostics.add("C004_RESERVED_FILE_INVALID", "log.md carries no frontmatter", file)
    # Headings inside fenced code blocks are not headings.
    fence = False
    for i, line in enumerate(re.split(r"\r?\n", text)):
        if re.match(r"^[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*(```|~~~)", line):
            fence = not fence
        if fence:
            continue
        h = re.match(r"^##[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+(.*)\Z", line)
        if h and not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}", h[1]):
            diagnostics.add(
                "C004_RESERVED_FILE_INVALID",
                f'log.md date headings must start with an ISO 8601 date: "{h[1]}"',
                file,
                i + 1,
            )


def _source_ids(fm: dict[str, Any]) -> list[Any]:
    sources = fm.get("sources")
    return [get(s, "id") for s in (sources if isinstance(sources, list) else []) if truthy(get(s, "id"))]


def _check_evidence(file: str, fm: dict[str, Any], diagnostics: Diagnostics) -> None:
    evidence = get(fm.get("moca"), "evidence")
    if not isinstance(evidence, list):
        return
    ids = _source_ids(fm)
    for e in evidence:
        source = get(e, "source")
        if isinstance(source, str) and source not in ids:
            diagnostics.add(
                "C006_EVIDENCE_SOURCE_UNKNOWN",
                f'evidence names source "{source}", which sources[] does not declare with that id',
                file,
            )


def _verify_evidence(
    file: str,
    fm: dict[str, Any],
    files: dict[str, str],
    data: dict[str, bytes],
    diagnostics: Diagnostics,
    limits: dict[str, int],
    source_text: dict[str, str],
    budget: dict[str, Any],
) -> list[EvidenceCheck]:
    """Checks each moca.evidence selector against the cited file, when it is inside the package and checkable."""
    evidence = get(fm.get("moca"), "evidence")
    if not isinstance(evidence, list):
        return []
    declared = fm.get("sources")
    sources: dict[Any, Any] = {}
    for s in declared if isinstance(declared, list) else []:
        sid = get(s, "id")
        if truthy(sid) and isinstance(sid, (str, int, float, bool)):
            sources[sid] = s
    checks: list[EvidenceCheck] = []
    for i, e in enumerate(evidence):
        key = get(e, "source")
        resource = get(sources.get(key), "resource") if isinstance(key, (str, int, float, bool)) else None
        if not isinstance(resource, str) or not _PATH_REF.match(resource):
            checks.append(EvidenceCheck(False))
            continue
        path, escapes = resolve_reference(file, resource)
        if escapes or not path or path not in files or not path.startswith(_EVIDENCE_DIRS):
            checks.append(EvidenceCheck(False))
            continue
        kind = source_kind(path)
        selector = get(e, "selector")
        if not kind or not isinstance(selector, dict):
            checks.append(EvidenceCheck(True))
            continue
        if i >= limits["maxEvidencePerNode"] or len(data[path]) > limits["maxSourceBytesChecked"]:
            checks.append(EvidenceCheck(True))
            continue
        if (
            budget["checks"] >= limits["maxEvidenceChecksPerPackage"]
            or budget["bytes"] + len(data[path]) > limits["maxEvidenceBytesPerPackage"]
        ):
            checks.append(EvidenceCheck(True))
            continue
        budget["checks"] += 1
        budget["bytes"] += len(data[path])
        if path not in source_text:
            # Contract §7: a leading byte order mark is not part of an evidence source.
            source_text[path] = data[path].decode("utf-8", errors="replace").removeprefix("\ufeff")
        prepared = None
        if selector.get("type") != "FragmentSelector":
            key = f"{path}\u0000{kind}"
            if key not in budget["prepared"]:
                budget["prepared"][key] = normalised_text(source_text[path], kind)
            prepared = budget["prepared"][key]
        matched = check_selector(selector, source_text[path], kind, prepared)
        if matched is False:
            diagnostics.add(
                "C011_EVIDENCE_SELECTOR_UNMATCHED",
                f'evidence {selector.get("type")} for source "{key}" does not match {path}',
                file,
            )
        checks.append(EvidenceCheck(True) if matched is None else EvidenceCheck(True, matched))
    return checks


def _check_window(file: str, fm: dict[str, Any], diagnostics: Diagnostics) -> None:
    from ._js import parse_date

    moca = fm.get("moca")
    start, until = parse_date(get(moca, "valid_from")), parse_date(get(moca, "valid_until"))
    if start is not None and until is not None and until <= start:
        diagnostics.add("C010_VALIDITY_WINDOW_INVALID", "moca.valid_until must be later than moca.valid_from", file)


_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def resolve_reference(from_file: str, ref: str) -> tuple[str | None, bool]:
    """A package-relative reference from a node: (path, escapes). See :func:`resolve_reference_reason`."""
    path, escapes, _ = resolve_reference_reason(from_file, ref)
    return path, escapes


def resolve_reference_reason(from_file: str, ref: str) -> tuple[str | None, bool, str]:
    """A package-relative reference from a node: (path, unsafe, reason).

    An absolute path or a drive prefix is unsafe, as is one that escapes the package root (C008);
    so is a malformed percent-encoding, which never raises.
    """
    stripped = re.sub(r"^<|>\Z", "", ref).split("#")[0].split("?")[0]
    try:
        clean = decode_uri_component(stripped)
    except ValueError:
        return None, True, "has a malformed percent-encoding"
    if clean == "":
        return None, False, ""
    if clean.startswith("/") or clean.startswith("\\") or _DRIVE.match(clean):
        return None, True, "is absolute"
    joined = posix_join(posix_dirname(from_file), clean)
    if joined == ".." or joined.startswith("../") or joined.startswith("/"):
        return None, True, "escapes the package root"
    return normalize("NFC", joined), False, ""


def _check_paths(file: str, fm: dict[str, Any], body: str, files: dict[str, str], diagnostics: Diagnostics) -> None:
    sources = fm.get("sources")
    for s in sources if isinstance(sources, list) else []:
        r = get(s, "resource")
        r = r if isinstance(r, str) else ""
        if not _PATH_REF.match(r):
            continue  # URLs and scope descriptors are not paths
        path, escapes, reason = resolve_reference_reason(file, r)
        if escapes:
            diagnostics.add("C008_UNSAFE_PATH", f'source resource "{r}" {reason}', file)
        elif path and path not in files:
            diagnostics.add("C007_LINK_UNRESOLVED", f'source resource "{r}" does not resolve to a package file', file)

    fence = False
    for line in re.split(r"\r?\n", body):
        if re.match(r"^[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*(```|~~~)", line):
            fence = not fence
        if fence:
            continue
        for m in _LINK.finditer(re.sub(r"`[^`]*`", "", line)):
            target = re.sub(r"^<|>\Z", "", m[1])
            if (_SCHEME.match(target) and not _DRIVE.match(target)) or target.startswith("#"):
                continue
            path, escapes, reason = resolve_reference_reason(file, target)
            if escapes:
                diagnostics.add("C008_UNSAFE_PATH", f'link "{target}" {reason}', file)
            elif path and path not in files:
                diagnostics.add("C007_LINK_UNRESOLVED", f'link "{target}" does not resolve', file)
