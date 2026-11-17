"""Content traversal: content/ is an Open Knowledge Format (OKF) v0.2 bundle (package spec §5, contract §5)."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ._js import decode_uri_component, get, js_sorted, js_trim, posix_dirname, posix_join, utf16_key
from .alternates import default_sync, range_to_reference, sync_problem
from .diagnostics import Diagnostics
from .evidence_text import check_selector, is_media_time_range, normalised_text, source_kind, webvtt
from .frontmatter import split_frontmatter
from .manifest import checked_credit
from .schemas import validate_against
from .unicode import normalize

if TYPE_CHECKING:
    from collections.abc import Callable

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
    located: dict[str, Any] | None = None  # contract §7: where a refined quote is spoken


@dataclass
class MediaDescription:
    """Package spec §5.7: one valid media description, with its source's resource as written."""

    source: str
    resource: str
    type: str
    duration: float | None = None
    digest: str | None = None
    transcript: str | None = None
    transcript_path: str | None = None  # the package path of the transcript; internal
    alternate_of: str | None = None
    sync: list[dict[str, Any]] | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"source": self.source, "resource": self.resource, "type": self.type}
        if self.duration is not None:
            out["duration"] = self.duration
        if self.digest is not None:
            out["digest"] = self.digest
        if self.transcript is not None:
            out["transcript"] = self.transcript
        if self.alternate_of is not None:
            out["alternateOf"] = self.alternate_of
            out["sync"] = [{"at": e["at"], "offset": e["offset"]} for e in self.sync or []]
        return out


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
    # Package spec §5.7: the valid media descriptions, in order.
    media: list[MediaDescription] = field(default_factory=list)
    # Package spec §4.13: the node's own credits, when they match the node schema.
    contributors: list[dict[str, Any]] | None = None


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
    evidence_budget: dict[str, int] | None = None,
) -> list[ContentNode]:
    source_text: dict[str, str] = {}
    # Contract §3: one budget of evidence checks and of source bytes scanned, shared by the package and its members
    # (`shared`); each source is normalised, and its cues parsed, once per package (`prepared`, `cues`).
    shared = evidence_budget if evidence_budget is not None else {"checks": 0, "bytes": 0}
    budget: dict[str, Any] = {"shared": shared, "prepared": {}, "cues": {}}
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
        # Package spec §5.1: evidence and media name a source by its id, so two sources with one id leave none chosen.
        repeated = _repeated_source_id(fm)
        if repeated is not None:
            diagnostics.add(
                "C002_FRONTMATTER_INVALID", f'sources has two entries with the id "{repeated}"; none is chosen', file
            )
            continue
        if not isinstance(fm.get("type"), str) or js_trim(fm["type"]) == "":
            diagnostics.add("C003_TYPE_MISSING", 'frontmatter needs a non-empty "type"', file)
            continue
        field_errors = validate_against("node", fm)
        for err in field_errors:
            diagnostics.add("C005_FIELD_INVALID", err, file)
        # Package spec §4.13: the node's own credits, when they match the node schema; images checked as in §4.6.
        moca_part = fm.get("moca")
        credits = moca_part.get("contributors") if isinstance(moca_part, dict) else None
        contributors = (
            [
                checked_credit(c, f"moca.contributors[{i}]", data, limits["maxImageBytes"], diagnostics, file)
                for i, c in enumerate(credits)
            ]
            if isinstance(credits, list)
            and not any(e.startswith("/moca/contributors") or e.startswith("/moca ") for e in field_errors)
            else None
        )
        _check_evidence(file, fm, diagnostics)
        _check_window(file, fm, diagnostics)
        _check_paths(file, fm, split.body, files, diagnostics)
        media = _media_descriptions(file, fm, files, diagnostics)
        checks = _verify_evidence(file, fm, files, data, diagnostics, limits, source_text, budget, media)

        rep = Representation(
            locale,
            file,
            fm,
            split.body,
            split.body_offset,
            file_digests.get(file),
            checks,
            media=media,
            contributors=contributors,
        )
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


def _repeated_source_id(fm: dict[str, Any]) -> str | None:
    """The first source id that two entries of the frontmatter's ``sources`` share, or None."""
    seen: set[str] = set()
    sources = fm.get("sources")
    for s in sources if isinstance(sources, list) else []:
        sid = s.get("id") if isinstance(s, dict) else None
        if not isinstance(sid, str):
            continue
        if sid in seen:
            return sid
        seen.add(sid)
    return None


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


def sources_by_id(fm: dict[str, Any]) -> dict[str, Any]:
    """The node's sources by id.

    Package spec §5.1: a source whose id is not a non-empty string has no id (the node schema reports C005), so
    nothing can name it. A repeated id never reaches here: it is C002.
    """
    out: dict[str, Any] = {}
    declared = fm.get("sources")
    for s in declared if isinstance(declared, list) else []:
        sid = s.get("id") if isinstance(s, dict) else None
        if isinstance(sid, str) and sid != "" and sid not in out:
            out[sid] = s
    return out


def _source_ids(fm: dict[str, Any]) -> list[str]:
    return list(sources_by_id(fm))


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


# Package spec §5.7: the keys of a media description and the form of each.
_MEDIA_KEYS = {"source", "type", "duration", "digest", "transcript", "alternateOf", "sync"}
_MEDIA_TYPE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}(?:[ \t]*;[^\n\r]*)?\Z"
)
_SHA256 = re.compile(r"^sha256:[a-f0-9]{64}\Z")


def _number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value == value
        and abs(value) != float("inf")
    )


def _well_formed_media(m: Any) -> bool:
    if not isinstance(m, dict) or any(k not in _MEDIA_KEYS for k in m):
        return False
    if not isinstance(m.get("source"), str) or m["source"] == "":
        return False
    if not isinstance(m.get("type"), str) or not _MEDIA_TYPE.match(m["type"]):
        return False
    if "duration" in m and not (_number(m["duration"]) and m["duration"] >= 0):
        return False
    if "digest" in m and not (isinstance(m["digest"], str) and _SHA256.match(m["digest"])):
        return False
    if "transcript" in m and not (isinstance(m["transcript"], str) and m["transcript"] != ""):
        return False
    if "alternateOf" in m and not (isinstance(m["alternateOf"], str) and m["alternateOf"] != ""):
        return False
    sync = m.get("sync")
    return "sync" not in m or (
        isinstance(sync, list) and len(sync) > 0 and all(_well_formed_sync_entry(e) for e in sync)
    )


def _well_formed_sync_entry(e: Any) -> bool:
    if not isinstance(e, dict) or any(k not in ("at", "offset") for k in e) or "offset" not in e:
        return False
    if not (_number(e.get("at")) and e["at"] >= 0):
        return False
    return e["offset"] is None or _number(e["offset"])


def _local_evidence_path(file: str, resource: Any, files: dict[str, str]) -> str | None:
    """The package path of a source's resource when it is a file under sources/ or media/, or None."""
    if not isinstance(resource, str) or not _PATH_REF.match(resource):
        return None
    path, escapes = resolve_reference(file, resource)
    if escapes or not path or path not in files or not path.startswith(_EVIDENCE_DIRS):
        return None
    return path


def _media_descriptions(
    file: str, fm: dict[str, Any], files: dict[str, str], diagnostics: Diagnostics
) -> list[MediaDescription]:
    """Package spec §5.7: the node's valid media descriptions; the invalid ones are reported and ignored."""
    listed = get(fm.get("moca"), "media")
    if not isinstance(listed, list):
        return []
    sources = sources_by_id(fm)
    described: set[str] = set()
    out: list[MediaDescription] = []
    raw: dict[int, dict[str, Any]] = {}
    for m in listed:
        if not _well_formed_media(m):
            continue  # the node schema reports it (C005)
        source = sources.get(m["source"])
        if source is None:
            diagnostics.add(
                "C006_EVIDENCE_SOURCE_UNKNOWN",
                f'media names source "{m["source"]}", which sources[] does not declare with that id',
                file,
            )
            continue
        resource = get(source, "resource")
        if not isinstance(resource, str):
            diagnostics.add(
                "C005_FIELD_INVALID", f'media describes source "{m["source"]}", which has no resource', file
            )
            continue
        if m["source"] in described:
            diagnostics.add(
                "C005_FIELD_INVALID",
                f'media describes source "{m["source"]}" twice; the later description is ignored',
                file,
            )
            continue
        described.add(m["source"])
        d = MediaDescription(m["source"], resource, m["type"], m.get("duration"), m.get("digest"))
        if "transcript" in m:
            path = _local_evidence_path(file, get(sources.get(m["transcript"]), "resource"), files)
            if path and source_kind(path) == "webvtt":
                d.transcript = m["transcript"]
                d.transcript_path = path
            else:
                diagnostics.add(
                    "C005_FIELD_INVALID",
                    f'media transcript "{m["transcript"]}" is not a source with a WebVTT file under sources/ or media/; '
                    "it is dropped",
                    file,
                )
        out.append(d)
        raw[id(d)] = m
    # §5.7, Alternates: checked once every description is known, so the order of descriptions does not matter.
    for d in out:
        m = raw[id(d)]
        if "alternateOf" not in m:
            if "sync" in m:
                diagnostics.add(
                    "C005_FIELD_INVALID", f'media "{d.source}" has sync but no alternateOf; sync is dropped', file
                )
            continue
        ref = next((x for x in out if x.source == m["alternateOf"]), None)
        sync = m.get("sync") or default_sync()
        if ref is None:
            problem: str | None = f'names "{m["alternateOf"]}", which is no valid description in this node'
        elif ref is d:
            problem = "names itself"
        elif "alternateOf" in raw[id(ref)]:
            problem = f'names "{ref.source}", which is an alternate itself'
        else:
            problem = sync_problem(sync)
        if problem:
            diagnostics.add(
                "C005_FIELD_INVALID",
                f'media "{d.source}" alternateOf {problem}; alternateOf and sync are dropped',
                file,
            )
            continue
        d.alternate_of = m["alternateOf"]
        d.sync = [{"at": e["at"], "offset": e["offset"]} for e in sync]
    return out


def _verify_evidence(
    file: str,
    fm: dict[str, Any],
    files: dict[str, str],
    data: dict[str, bytes],
    diagnostics: Diagnostics,
    limits: dict[str, int],
    source_text: dict[str, str],
    budget: dict[str, Any],
    media: list[MediaDescription] | None = None,
) -> list[EvidenceCheck]:
    """Checks each moca.evidence selector against the cited file, when it is inside the package and checkable."""
    evidence = get(fm.get("moca"), "evidence")
    if not isinstance(evidence, list):
        return []
    sources: dict[Any, Any] = sources_by_id(fm)
    descriptions = {d.source: d for d in media or []}
    checks: list[EvidenceCheck] = []
    for i, e in enumerate(evidence):
        key = get(e, "source")
        resource = get(sources.get(key), "resource") if isinstance(key, (str, int, float, bool)) else None
        path = _local_evidence_path(file, resource, files)
        selector = get(e, "selector")
        # Contract §7: a time range is checked against the cited WebVTT file, or the transcript of the cited media,
        # and bounded by the media's duration. A time range checked this way is evidence checkable in the package.
        duration: float | None = None
        to_ref: Callable[[tuple[float, float]], tuple[float, float] | None] | None = None
        if is_media_time_range(selector) and (not path or source_kind(path) != "webvtt"):
            d = descriptions.get(key) if isinstance(key, str) else None
            ref = descriptions.get(d.alternate_of) if d is not None and d.alternate_of is not None else None
            if d is not None and d.transcript_path:
                path = d.transcript_path
                duration = d.duration
            elif d is not None and ref is not None and ref.transcript_path:
                # §5.7: an alternate with no transcript of its own is checked through its reference.
                path = ref.transcript_path
                duration = ref.duration
                alt_sync = d.sync or default_sync()
                alt_duration = d.duration

                # An alternate's own duration bounds the range too, when it declares one.
                def to_ref(
                    window: tuple[float, float], s: list[dict[str, Any]] = alt_sync, dur: float | None = alt_duration
                ) -> tuple[float, float] | None:
                    if dur is not None and window[1] != float("inf") and window[1] > dur:
                        return None
                    return range_to_reference(s, window)
        elif path and source_kind(path) == "webvtt":
            duration = next((d.duration for d in media or [] if d.transcript == key), None)
        if not path:
            checks.append(EvidenceCheck(False))
            continue
        kind = source_kind(path)
        if not kind or not isinstance(selector, dict):
            checks.append(EvidenceCheck(True))
            continue
        if i >= limits["maxEvidencePerNode"] or len(data[path]) > limits["maxSourceBytesChecked"]:
            checks.append(EvidenceCheck(True))
            continue
        shared = budget["shared"]
        if (
            shared["checks"] >= limits["maxEvidenceChecksPerPackage"]
            or shared["bytes"] + len(data[path]) > limits["maxEvidenceBytesPerPackage"]
        ):
            checks.append(EvidenceCheck(True))
            continue
        shared["checks"] += 1
        shared["bytes"] += len(data[path])
        if path not in source_text:
            # Contract §7: a leading byte order mark is not part of an evidence source.
            source_text[path] = data[path].decode("utf-8", errors="replace").removeprefix("\ufeff")
        prepared = None
        cues = None
        if selector.get("type") == "FragmentSelector":
            if kind == "webvtt":
                if path not in budget["cues"]:
                    budget["cues"][path] = webvtt(source_text[path])[0]
                cues = budget["cues"][path]
        else:
            key = f"{path}\u0000{kind}"
            if key not in budget["prepared"]:
                budget["prepared"][key] = normalised_text(source_text[path], kind)
            prepared = budget["prepared"][key]
        report: dict[str, Any] = {}
        matched = check_selector(selector, source_text[path], kind, prepared, duration, to_ref, report, cues)
        if matched is False:
            diagnostics.add(
                "C011_EVIDENCE_SELECTOR_UNMATCHED",
                f'evidence {selector.get("type")} for source "{key}" does not match {path}',
                file,
            )
        checks.append(
            EvidenceCheck(True)
            if matched is None
            else EvidenceCheck(True, matched, report.get("located") if matched else None)
        )
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
