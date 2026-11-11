"""Sidecar indexes (moca-sidecar-index-spec.md)."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ._js import get, js_trim, json_loads, posix_normalize, truthy
from .content import Representation
from .diagnostics import Diagnostic, Diagnostics
from .digest import utf8
from .schemas import validate_against
from .source import TargetError, open_source

if TYPE_CHECKING:
    from .reader import PackageResult

SIDECAR_MANIFEST = "index.json"
PORTABLE_FORMAT = "moca-jsonl-v1"


@dataclass
class SidecarBinding:
    usable: bool = False
    index: Any = None
    chunks: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)


def bind_sidecar(target: Any, pkg: PackageResult, strict: bool = False) -> SidecarBinding:
    """Checks a sidecar against a package and returns the chunks a Library can search.

    A sidecar that fails any check is ignored: the package stays fully usable without it.
    """
    diagnostics = Diagnostics(strict)
    out = SidecarBinding(diagnostics=diagnostics.items)
    try:
        source = open_source(target)
        listed = {e.path: e for e in source.list() if e.kind == "file"}
    except TargetError as err:
        diagnostics.add("S001_SIDECAR_INVALID", str(err))
        return out
    if SIDECAR_MANIFEST not in listed:
        diagnostics.add("S001_SIDECAR_INVALID", "the sidecar has no index.json")
        return out
    try:
        index = json_loads(source.read(SIDECAR_MANIFEST).decode("utf-8", errors="replace"))
    except ValueError as err:
        diagnostics.add("S001_SIDECAR_INVALID", f"index.json is not valid JSON: {err}", SIDECAR_MANIFEST)
        return out
    out.index = index
    errors = validate_against("sidecarIndex", index)
    for e in errors:
        diagnostics.add("S001_SIDECAR_INVALID", e, SIDECAR_MANIFEST)
    if errors:
        return out

    m = pkg.manifest or {}
    target_ref = index["target"]
    if target_ref.get("id") != m.get("id") or target_ref.get("version") != m.get("version"):
        diagnostics.add(
            "S002_SIDECAR_TARGET_MISMATCH",
            f"sidecar is bound to {target_ref.get('id')}@{target_ref.get('version')}, not {m.get('id')}@{m.get('version')}",
            SIDECAR_MANIFEST,
        )
        return out
    if target_ref.get("digest") != pkg.digest:
        diagnostics.add(
            "S003_SIDECAR_STALE",
            f"sidecar was built for {target_ref.get('digest')}; the package is {pkg.digest}",
            SIDECAR_MANIFEST,
        )
        return out
    storage = index["storage"]
    if storage.get("format") != PORTABLE_FORMAT:
        diagnostics.add(
            "S005_SIDECAR_FORMAT_UNKNOWN",
            f'payload format "{storage.get("format")}" is not {PORTABLE_FORMAT}; the sidecar is ignored',
            SIDECAR_MANIFEST,
        )
        return out
    payload_path = posix_normalize(storage["file"])
    if payload_path.startswith("..") or payload_path.startswith("/") or payload_path not in listed:
        diagnostics.add(
            "S001_SIDECAR_INVALID",
            f'storage.file "{storage["file"]}" is missing or outside the sidecar',
            SIDECAR_MANIFEST,
        )
        return out

    reps: dict[str, Representation] = {}
    for node in pkg.nodes:
        for rep in node.representations:
            reps[f"{node.path}\0{rep.locale or ''}"] = rep
    lines = [
        line for line in source.read(payload_path).decode("utf-8", errors="replace").split("\n") if js_trim(line) != ""
    ]
    counts: dict[str, set[Any]] = {}
    bad = 0
    for i, line in enumerate(lines):
        try:
            item = json_loads(line)
        except ValueError:
            diagnostics.add("S004_SIDECAR_ITEM_INVALID", "payload line is not JSON", payload_path, i + 1)
            bad += 1
            continue
        problem = _check_item(item, reps, index)
        if problem:
            diagnostics.add("S004_SIDECAR_ITEM_INVALID", problem, payload_path, i + 1)
            bad += 1
            continue
        counts.setdefault(_key(item), set()).add(item["chunkIndex"])
        out.chunks.append(item)
    for item in out.chunks:
        if len(counts[_key(item)]) != item["chunkCount"]:
            diagnostics.add(
                "S004_SIDECAR_ITEM_INVALID",
                f"{item['path']}: chunkCount is {item['chunkCount']} but {len(counts[_key(item)])} chunk(s) are present",
                payload_path,
            )
            bad += 1
            break
    if bad == 0 and truthy(storage.get("vectors")):
        bad += _attach_vectors(source, listed, index, out.chunks, len(lines), diagnostics)
    out.usable = bad == 0
    if not out.usable:
        out.chunks = []
    return out


def _key(item: dict[str, Any]) -> str:
    locale = item.get("locale")
    return f"{item['path']}\0{locale if truthy(locale) else ''}"


def chunk_text(chunk: dict[str, Any], rep: Representation) -> str:
    """A chunk's text: its bytes of the node file, clipped to the body. Contract §9.1: never the sidecar's text."""
    return _slice_body(rep, chunk["start"], chunk["end"])


def _slice_body(rep: Representation, start: int, end: int) -> str:
    body = utf8(rep.body)
    lo = max(start - rep.body_offset, 0)
    hi = min(end - rep.body_offset, len(body))
    return body[lo:hi].decode("utf-8", errors="replace") if hi > lo else ""


def _attach_vectors(
    source: Any,
    listed: dict[str, Any],
    index: dict[str, Any],
    chunks: list[dict[str, Any]],
    count: int,
    diagnostics: Diagnostics,
) -> int:
    """Reads storage.vectors (little-endian float32, one row per item) onto the chunks. Returns 1 on a problem."""
    vectors = index["storage"]["vectors"]
    file, dimensions = vectors.get("file"), vectors.get("dimensions")
    path = posix_normalize(file)
    if path.startswith("..") or path.startswith("/") or path not in listed:
        diagnostics.add(
            "S001_SIDECAR_INVALID", f'storage.vectors.file "{file}" is missing or outside the sidecar', SIDECAR_MANIFEST
        )
        return 1
    model_dims = get(index.get("model"), "dimensions")
    if truthy(model_dims) and model_dims != dimensions:
        diagnostics.add(
            "S004_SIDECAR_ITEM_INVALID",
            f"storage.vectors has {dimensions} dimensions, model declares {model_dims}",
            SIDECAR_MANIFEST,
        )
        return 1
    data = source.read(path)
    if len(data) != count * dimensions * 4:
        diagnostics.add(
            "S004_SIDECAR_ITEM_INVALID",
            f"{path} has {len(data)} bytes; {count} items x {dimensions} float32 needs {count * dimensions * 4}",
            path,
        )
        return 1
    for i, chunk in enumerate(chunks):
        chunk["vector"] = list(struct.unpack_from(f"<{dimensions}f", data, i * dimensions * 4))
    return 0


def _is_int(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())


def _check_item(item: Any, reps: dict[str, Representation], index: dict[str, Any]) -> str | None:
    if not isinstance(item, (dict, list)) or not truthy(item):
        return "item is not an object"
    if not isinstance(item, dict):
        return 'path must be relative to content/ without ".." segments'
    path = item.get("path")
    if not isinstance(path, str) or path.startswith("/") or ".." in path.split("/"):
        return 'path must be relative to content/ without ".." segments'
    rep = reps.get(_key(item))
    if rep is None:
        locale = item.get("locale")
        return f'path "{path}"{f" ({locale})" if truthy(locale) else ""} is not a content node of the package'
    count: Any = item.get("chunkCount")
    idx: Any = item.get("chunkIndex")
    if not _is_int(count) or count < 1:
        return "chunkCount must be a positive integer"
    if not _is_int(idx) or idx < 0 or idx >= count:
        return "0 <= chunkIndex < chunkCount must hold"
    start: Any = item.get("start")
    end: Any = item.get("end")
    if not _is_int(start) or not _is_int(end) or start < 0 or end < start:
        return "start and end must be byte offsets with 0 <= start <= end"
    file_end = rep.body_offset + len(utf8(rep.body))
    if end > file_end:
        return f"end {end} is beyond the end of the file ({file_end})"
    # Sidecar §5: a chunk lies inside the node's body, and any text it carries is exactly the package's bytes there.
    if start < rep.body_offset:
        return f"start {start} is inside the frontmatter (the body starts at {rep.body_offset})"
    if "text" in item and item["text"] != _slice_body(rep, start, end):
        return "text is not the package's text at start..end"
    if "vector" in item:
        vec = item["vector"]
        if not isinstance(vec, list) or any(not isinstance(v, (int, float)) or isinstance(v, bool) for v in vec):
            return "vector must be an array of numbers"
        model_dims = get(index.get("model"), "dimensions")
        if truthy(model_dims) and len(vec) != model_dims:
            return f"vector has {len(vec)} dimensions, model declares {model_dims}"
    return None
