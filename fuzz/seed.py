"""Builds the fuzz seed corpora from moca-spec's conformance fixtures and example packages.

<corpus dir>: every fixture archive as it is, and every fixture folder zipped (open_search.py).
<corpus dir>-files: each file of the base fixture (``MOCA_FUZZ_BASE``, as in package_files.py), led by a byte choosing which file it replaces
(package_files.py). Usage: python fuzz/seed.py <moca-spec dir> <corpus dir>
"""

import hashlib
import io
import os
import sys
import zipfile
from pathlib import Path

MAX = 1024 * 1024  # keep seeds small, so each run explores more


def save(data: bytes, folder: Path) -> int:
    if len(data) > MAX:
        return 0
    (folder / hashlib.sha256(data).hexdigest()[:16]).write_bytes(data)
    return 1


def zipped(folder: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                z.writestr(p.relative_to(folder).as_posix(), p.read_bytes())
    return buf.getvalue()


def main(spec: Path, out: Path) -> None:
    files_out = out.parent / f"{out.name}-files"
    out.mkdir(parents=True, exist_ok=True)
    files_out.mkdir(parents=True, exist_ok=True)
    fixtures = spec / "conformance" / "fixtures"
    n = 0
    for entry in sorted(fixtures.iterdir()):
        if entry.is_dir():
            n += save(zipped(entry), out)
        elif entry.is_file() and entry.suffix in (".zip", ".moca"):
            n += save(entry.read_bytes(), out)
    for example in sorted((spec / "dist" / "examples").glob("*.moca")):
        n += save(example.read_bytes(), out)
    # Seeds for package_files.py, in the target's file order (sorted paths), each led by the byte choosing it.
    base = fixtures / os.environ.get("MOCA_FUZZ_BASE", "structure-procedure")
    paths = sorted(p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file())
    for i, path in enumerate(paths):
        n += save(bytes([i]) + (base / path).read_bytes(), files_out)
    print(f"{n} seed(s) in {out} and {files_out}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python fuzz/seed.py <moca-spec dir> <corpus dir>")
    main(Path(sys.argv[1]), Path(sys.argv[2]))
