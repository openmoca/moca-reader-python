"""Package sources: a directory, a ``.moca`` Zip archive, or a host-supplied object (Reader contract §3).

Every source lists its entries and returns the bytes of a listed file. A source never follows a symbolic
link and never hides one: symlinks and other non-regular files are listed with their kind, so the digest
and the Reader can refuse them (package spec §6). Entries whose name begins with "." are not part of a
package and are skipped, with their subtrees.
"""

from __future__ import annotations

import io
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
    # Contract §3: evidence work for the whole read, the package and all its members together, is bounded too.
    "maxEvidenceChecksPerPackage": 10_000,
    "maxEvidenceBytesPerPackage": 256 * 1024 * 1024,
    # Contract §3 and package spec §7.1: composition is bounded in depth and in members resolved per read.
    "maxMemberDepth": 8,
    "maxMembers": 4096,
    "maxMemberBytes": 1024 * 1024 * 1024,
    # Encrypted packages §4: the scrypt work factor (log2 N) a Reader runs, at most.
    "maxScryptWorkFactor": 20,
    # Package spec §4.6: the bytes of one manifest image (and of an envelope's cover copy).
    "maxImageBytes": 1024 * 1024,
    # Contract §3: attestation files in one package, and the bytes of one of them.
    "maxAttestations": 256,
    "maxAttestationBytes": 1024 * 1024,
}


@dataclass(frozen=True)
class SourceEntry:
    path: str
    kind: str  # file | symlink | other | unreadable
    size: int | None = None
    method: int | None = None  # the Zip compression method, for archives


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
        # Encrypted packages §2: an envelope must have no hidden entry, so an archive keeps the names it skips.
        self.hidden_entries: list[str] = []
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
    # purpose bit 11) is rejected, not guessed. The name is the central directory's file name field
    # (orig_filename): zipfile's filename cuts it at NUL, changes separators, and may take the Info-ZIP Unicode
    # path extra field instead, which contract §3 ignores.
    if "\0" in info.orig_filename:
        raise TargetError("T003_ARCHIVE_REJECTED", "archive entry name contains NUL")
    if info.flag_bits & 0x800:
        return info.orig_filename
    if not info.orig_filename.isascii():
        raise TargetError("T003_ARCHIVE_REJECTED", "archive entry name is not marked as UTF-8")
    return info.orig_filename


class _BufferFile(io.RawIOBase):
    """A read-only, seekable file over a buffer, without copying it (io.BytesIO copies a bytearray)."""

    def __init__(self, buffer: bytes | bytearray | memoryview) -> None:
        super().__init__()
        self._view = memoryview(buffer).cast("B")
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        n = max(0, min(len(b), len(self._view) - self._pos))
        b[:n] = self._view[self._pos : self._pos + n]
        self._pos += n
        return n

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: len(self._view)}[whence]
        if base + offset < 0:
            raise ValueError("negative seek position")
        self._pos = base + offset
        return self._pos

    def tell(self) -> int:
        return self._pos


def archive_source(
    archive: str | os.PathLike[str] | bytes | bytearray | memoryview, limits: dict[str, int] | None = None
) -> PackageSource:
    """Opens a .moca/.zip archive in memory, without extracting it. A buffer is read in place; a file is read
    into memory once and closed."""
    lim = {**DEFAULT_LIMITS, **(limits or {})}
    in_memory = isinstance(archive, (bytes, bytearray, memoryview))
    try:
        buffer = archive if isinstance(archive, (bytes, bytearray, memoryview)) else Path(archive).read_bytes()
    except OSError as err:
        raise TargetError("T003_ARCHIVE_REJECTED", f"archive could not be opened: {err}") from err
    check_archive_records(buffer)
    try:
        zf = zipfile.ZipFile(_BufferFile(buffer))
        infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, NotImplementedError) as err:
        raise TargetError("T003_ARCHIVE_REJECTED", f"archive could not be opened: {err}") from err
    if len(infos) > lim["maxEntries"]:
        raise TargetError(
            "T003_ARCHIVE_REJECTED", f"archive has {len(infos)} entries, over the {lim['maxEntries']} limit"
        )
    total = 0
    listed: list[SourceEntry] = []
    hidden: list[str] = []
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
            hidden.append(path)
            continue
        mode = (info.external_attr >> 16) & 0o170000
        kind = "file"
        if mode == 0o120000:
            kind = "symlink"
        elif mode not in (0, 0o100000):
            kind = "other"
        listed.append(SourceEntry(path, kind, info.file_size, info.compress_type))
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
        # An entry zipfile cannot read (encrypted, damaged, or not what its directory entry says) is unreadable.
        except (zipfile.BadZipFile, EOFError, zlib.error, RuntimeError, ValueError, NotImplementedError) as err:
            raise OSError(f"entry cannot be read: {err}") from err
        if len(data) != info.file_size:
            raise OSError(f"entry is {len(data)} bytes, not the {info.file_size} its header declares")
        return data

    location = None if in_memory else os.fspath(archive)  # type: ignore[arg-type]
    source = PackageSource("archive", lambda: listed, read, location)
    source.hidden_entries = hidden
    return source


_END = 22  # the fixed part of the end-of-central-directory record


def check_archive_records(buffer: bytes | bytearray | memoryview) -> None:
    """Contract §3, "Directory": the records every Zip reader must agree on, checked before zipfile reads anything.
    There is exactly one end-of-central-directory record that ends at the end of the file; it is not part of a
    multi-disk or Zip64 archive; the central directory holds exactly the entries it declares; and each entry's
    local header is where the directory says, with the same name and compression method. Anything else is T003."""
    buf = memoryview(buffer).cast("B")
    size_of = len(buf)

    def u16(at: int) -> int:
        return int.from_bytes(buf[at : at + 2], "little")

    def u32(at: int) -> int:
        return int.from_bytes(buf[at : at + 4], "little")

    def reject(why: str) -> None:
        raise TargetError("T003_ARCHIVE_REJECTED", f"archive {why}")

    end = -1
    for p in range(size_of - _END, max(0, size_of - _END - 0xFFFF) - 1, -1):
        if u32(p) == 0x06054B50 and p + _END + u16(p + 20) == size_of:
            if end != -1:
                reject("has more than one end-of-central-directory record")
            end = p
    if end == -1:
        reject("has no end-of-central-directory record at its end")
    count, directory_size, offset = u16(end + 10), u32(end + 12), u32(end + 16)
    if u16(end + 4) != 0 or u16(end + 6) != 0 or u16(end + 8) != count:
        reject("is part of a multi-disk archive")
    if (
        count == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or offset == 0xFFFFFFFF
        or (end >= 20 and u32(end - 20) == 0x07064B50)
    ):
        reject("uses Zip64, which this version does not read")
    stop = offset + directory_size
    if stop > end:
        reject("has a central directory that runs into its end record")
    p = offset
    for _ in range(count):
        if p + 46 > stop or u32(p) != 0x02014B50:
            reject("has a central directory that does not hold the entries it declares")
        name_length = u16(p + 28)
        following = p + 46 + name_length + u16(p + 30) + u16(p + 32)
        if following > stop:
            reject("has a central directory that does not hold the entries it declares")
        local = u32(p + 42)
        if u16(p + 34) != 0 or local + 30 + name_length > offset or u32(local) != 0x04034B50:
            reject("has an entry whose local header is not where the central directory says")
        same_name = (
            u16(local + 26) == name_length
            and buf[local + 30 : local + 30 + name_length] == buf[p + 46 : p + 46 + name_length]
        )
        if not same_name or u16(local + 8) != u16(p + 10):
            reject("has an entry whose local header does not match the central directory")
        p = following
    if p != stop:
        reject("has a central directory that does not hold the entries it declares")


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


def _starts_with_zip_signature(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) in (b"PK\x03\x04", b"PK\x05\x06")
    except OSError:
        return False


def open_source(target: Any, limits: dict[str, int] | None = None) -> PackageSource:
    """A directory path, a .moca/.zip path, a PackageSource, or a host source object."""
    if isinstance(target, PackageSource):
        return target
    if not isinstance(target, (str, os.PathLike)) and callable(getattr(target, "list", None)):
        return host_source(target, limits)
    # Interface §3: archive bytes are a target too.
    # A bytearray or memoryview (decrypted bytes) is read in place, never copied.
    if isinstance(target, (bytes, bytearray, memoryview)):
        return archive_source(target, limits)
    if not isinstance(target, (str, os.PathLike)) or not os.path.exists(target):
        raise TargetError("T001_TARGET_NOT_FOUND", f"target does not exist: {target}")
    path = os.fspath(target)
    if os.path.isdir(path):
        return directory_source(path, limits)
    if os.path.isfile(path) and path.lower().endswith((".moca", ".zip")):
        return archive_source(path, limits)
    # Encrypted packages §2: an envelope (conventionally .mocae) is recognised by content, so any file that starts
    # with a Zip signature is read as an archive.
    if os.path.isfile(path) and _starts_with_zip_signature(path):
        return archive_source(path, limits)
    raise TargetError(
        "T002_MANIFEST_NOT_FOUND", f"target exists but is neither a directory nor a .moca/.zip archive: {path}"
    )
