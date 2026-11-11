"""Package sources: a directory, a ``.moca`` Zip archive, or a host-supplied object (Reader contract §3).

Every source lists its entries and returns the bytes of a listed file. A source never follows a symbolic
link and never hides one: symlinks and other non-regular files are listed with their kind, so the digest
and the Reader can refuse them (package spec §6). Entries whose name begins with "." are not part of a
package and are skipped, with their subtrees.
"""

from __future__ import annotations

import os
import stat
import zipfile
import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ._js import js_sorted, utf16_key

DEFAULT_LIMITS: dict[str, int] = {
    "maxEntries": 20_000,
    "maxBytes": 512 * 1024 * 1024,
    "maxFrontmatterBytes": 64 * 1024,
    "maxStructureBytes": 4 * 1024 * 1024,
    "maxTriples": 100_000,
    "maxEvidencePerNode": 256,
    "maxSourceBytesChecked": 8 * 1024 * 1024,
    # Contract §3: evidence work for the whole package is bounded too.
    "maxEvidenceChecksPerPackage": 10_000,
    "maxEvidenceBytesPerPackage": 256 * 1024 * 1024,
    # Contract §3 and package spec §7.1: composition is bounded in depth and in members resolved per read.
    "maxMemberDepth": 8,
    "maxMembers": 256,
}


@dataclass(frozen=True)
class SourceEntry:
    path: str
    kind: str  # file | symlink | other | unreadable
    size: int | None = None


class TargetError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@runtime_checkable
class HostSource(Protocol):
    """What a host supplies to read a package from memory, blob storage or a database."""

    def list(self) -> Iterable[str | SourceEntry]: ...

    def read(self, path: str) -> bytes: ...


class PackageSource:
    """A uniform view of a package's entries."""

    def __init__(
        self,
        kind: str,
        entries: Callable[[], list[SourceEntry]],
        reader: Callable[[str], bytes],
        location: str | None = None,
    ) -> None:
        self.kind = kind
        self.location = location
        self._entries = entries
        self._reader = reader
        self._cache: list[SourceEntry] | None = None

    def list(self) -> list[SourceEntry]:
        if self._cache is None:
            self._cache = self._entries()
        return self._cache

    def read(self, path: str) -> bytes:
        return self._reader(path)


def is_hidden_segment(name: str) -> bool:
    return name.startswith(".")


def directory_source(root: str | os.PathLike[str], limits: dict[str, int] | None = None) -> PackageSource:
    root_dir = os.fspath(root)
    lim = {**DEFAULT_LIMITS, **(limits or {})}
    read_bytes = [0]

    def walk() -> list[SourceEntry]:
        out: list[SourceEntry] = []

        def visit(abs_dir: str, rel_dir: str) -> None:
            try:
                names = os.listdir(abs_dir)
            except OSError:
                out.append(SourceEntry(rel_dir or ".", "unreadable"))
                return
            for name in js_sorted(names):
                if is_hidden_segment(name):
                    continue
                abs_path = os.path.join(abs_dir, name)
                rel = f"{rel_dir}/{name}" if rel_dir else name
                try:
                    st = os.lstat(abs_path)
                except OSError:
                    out.append(SourceEntry(rel, "unreadable"))
                    continue
                if stat.S_ISLNK(st.st_mode):
                    out.append(SourceEntry(rel, "symlink"))
                elif stat.S_ISDIR(st.st_mode):
                    visit(abs_path, rel)
                elif stat.S_ISREG(st.st_mode):
                    out.append(SourceEntry(rel, "file", st.st_size))
                else:
                    out.append(SourceEntry(rel, "other"))

        visit(root_dir, "")
        # Contract §3: the entry and byte limits apply to every source, directories included.
        if len(out) > lim["maxEntries"]:
            raise TargetError(
                "T003_ARCHIVE_REJECTED", f"directory has {len(out)} entries, over the {lim['maxEntries']} limit"
            )
        if sum(e.size or 0 for e in out) > lim["maxBytes"]:
            raise TargetError("T003_ARCHIVE_REJECTED", f"directory exceeds the {lim['maxBytes']}-byte limit")
        return out

    def read(path: str) -> bytes:
        file = Path(root_dir, *path.split("/"))
        # Never follow a link swapped in after listing.
        if not stat.S_ISREG(os.lstat(file).st_mode):
            raise OSError(f"{path} is no longer a regular file")
        data = file.read_bytes()
        read_bytes[0] += len(data)
        if read_bytes[0] > lim["maxBytes"]:
            raise TargetError("T003_ARCHIVE_REJECTED", f"directory exceeds the {lim['maxBytes']}-byte limit")
        return data

    return PackageSource("directory", walk, read, root_dir)


def _assert_safe_archive_path(name: str) -> None:
    if (
        "\\" in name
        or name.startswith("/")
        or (len(name) > 1 and name[0].isascii() and name[0].isalpha() and name[1] == ":")
    ):
        raise TargetError("T003_ARCHIVE_REJECTED", f'archive entry "{name}" is absolute or uses backslashes')
    if ".." in name.split("/"):
        raise TargetError("T003_ARCHIVE_REJECTED", f'archive entry "{name}" contains a ".." segment')
    # Contract §3: no NUL, and no empty or "." segments (a trailing "/" marks a directory).
    if "\0" in name or any(s in ("", ".") for s in name.rstrip("/").split("/")):
        raise TargetError("T003_ARCHIVE_REJECTED", f'archive entry "{name}" has an empty, "." or NUL segment')


def _entry_name(info: zipfile.ZipInfo) -> str:
    # Contract §3: entry names are UTF-8. A name with bytes outside ASCII and without the UTF-8 flag (general
    # purpose bit 11) is rejected, not guessed. zipfile cuts names at NUL; orig_filename keeps it.
    if "\0" in info.orig_filename:
        raise TargetError("T003_ARCHIVE_REJECTED", "archive entry name contains NUL")
    if info.flag_bits & 0x800:
        return info.filename
    if not info.orig_filename.isascii():
        raise TargetError("T003_ARCHIVE_REJECTED", "archive entry name is not marked as UTF-8")
    return info.orig_filename


def archive_source(archive: str | os.PathLike[str] | bytes, limits: dict[str, int] | None = None) -> PackageSource:
    """Opens a .moca/.zip archive in memory, without extracting it."""
    lim = {**DEFAULT_LIMITS, **(limits or {})}
    try:
        import io

        zf = zipfile.ZipFile(io.BytesIO(archive) if isinstance(archive, bytes) else os.fspath(archive))
        infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, ValueError) as err:
        raise TargetError("T003_ARCHIVE_REJECTED", f"archive could not be opened: {err}") from err
    if len(infos) > lim["maxEntries"]:
        raise TargetError(
            "T003_ARCHIVE_REJECTED", f"archive has {len(infos)} entries, over the {lim['maxEntries']} limit"
        )
    total = 0
    listed: list[SourceEntry] = []
    by_path: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        name = _entry_name(info)
        _assert_safe_archive_path(name)
        total += info.file_size
        if total > lim["maxBytes"]:
            raise TargetError("T003_ARCHIVE_REJECTED", f"archive expands beyond the {lim['maxBytes']}-byte limit")
        if name.endswith("/"):
            continue
        path = name.rstrip("/")
        if any(is_hidden_segment(s) for s in path.split("/")):
            continue
        mode = (info.external_attr >> 16) & 0o170000
        kind = "file"
        if mode == 0o120000:
            kind = "symlink"
        elif mode not in (0, 0o100000):
            kind = "other"
        listed.append(SourceEntry(path, kind, info.file_size))
        by_path[path] = info
    listed.sort(key=lambda e: utf16_key(e.path))

    def read(path: str) -> bytes:
        info = by_path.get(path)
        if info is None:
            raise KeyError(f"no such entry: {path}")
        # Contract §3: only stored and deflated entries are read; any other method is unreadable (P002).
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise OSError(f"unsupported compression method {info.compress_type}")
        # Contract §3: a bad CRC-32, or bytes that do not fit the declared size, make the entry unreadable (P002).
        try:
            data = zf.read(info)
        except (zipfile.BadZipFile, EOFError, zlib.error) as err:
            raise OSError(f"entry cannot be read: {err}") from err
        if len(data) != info.file_size:
            raise OSError(f"entry is {len(data)} bytes, not the {info.file_size} its header declares")
        return data

    location = None if isinstance(archive, bytes) else os.fspath(archive)
    return PackageSource("archive", lambda: listed, read, location)


def host_source(host: Any, limits: dict[str, int] | None = None) -> PackageSource:
    """Wraps a host-supplied source: an object with ``list()`` (paths or entries) and ``read(path)``."""
    lim = {**DEFAULT_LIMITS, **(limits or {})}
    listed_paths: set[str] = set()
    read_bytes = [0]

    def entries() -> list[SourceEntry]:
        raw = [SourceEntry(e, "file") if isinstance(e, str) else e for e in host.list()]
        if len(raw) > lim["maxEntries"]:
            raise TargetError(
                "T003_ARCHIVE_REJECTED", f"source lists {len(raw)} entries, over the {lim['maxEntries']} limit"
            )
        total = 0
        for e in raw:
            _assert_safe_archive_path(e.path)
            total += e.size or 0
            if total > lim["maxBytes"]:
                raise TargetError("T003_ARCHIVE_REJECTED", f"source exceeds the {lim['maxBytes']}-byte limit")
        kept = [e for e in raw if not any(is_hidden_segment(s) for s in e.path.split("/"))]
        kept.sort(key=lambda e: utf16_key(e.path))
        listed_paths.update(e.path for e in kept)
        return kept

    def read(path: str) -> bytes:
        if path not in listed_paths:
            raise KeyError(f"path was not listed: {path}")
        data = bytes(host.read(path))
        # Contract §3: a host source need not list sizes, so the byte limit is also enforced on what is read.
        read_bytes[0] += len(data)
        if read_bytes[0] > lim["maxBytes"]:
            raise TargetError("T003_ARCHIVE_REJECTED", f"source exceeds the {lim['maxBytes']}-byte limit")
        return data

    return PackageSource("host", entries, read)


def open_source(target: Any, limits: dict[str, int] | None = None) -> PackageSource:
    """A directory path, a .moca/.zip path, a PackageSource, or a host source object."""
    if isinstance(target, PackageSource):
        return target
    if not isinstance(target, (str, os.PathLike)) and callable(getattr(target, "list", None)):
        return host_source(target, limits)
    # Interface §3: archive bytes are a target too.
    if isinstance(target, (bytes, bytearray, memoryview)):
        return archive_source(bytes(target), limits)
    if not isinstance(target, (str, os.PathLike)) or not os.path.exists(target):
        raise TargetError("T001_TARGET_NOT_FOUND", f"target does not exist: {target}")
    path = os.fspath(target)
    if os.path.isdir(path):
        return directory_source(path, limits)
    if os.path.isfile(path) and path.lower().endswith((".moca", ".zip")):
        return archive_source(path, limits)
    raise TargetError(
        "T002_MANIFEST_NOT_FOUND", f"target exists but is neither a directory nor a .moca/.zip archive: {path}"
    )
