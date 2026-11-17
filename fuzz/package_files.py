"""Fuzz target: a valid package with one file replaced by fuzzed bytes, read through a host source.

The mutations then reach the manifest, frontmatter, YAML, Turtle and evidence parsers instead of stopping at the
archive's checksums. The base is a valid fixture from moca-spec's corpus, ``MOCA_FUZZ_BASE`` (by default
``structure-procedure``: a manifest, Markdown with frontmatter, and Turtle), found through ``MOCA_SPEC_DIR`` or
moca-spec beside this repository. The rule is the same as open_search.py: ``read_package`` never raises, and a package that
reads as valid searches without raising.

Usage: python fuzz/package_files.py <corpus dirs> [libFuzzer options]
"""

import os
import sys
from pathlib import Path

import atheris

with atheris.instrument_imports(include=["moca_reader"]):
    from moca_reader import LexicalBackend, Library, Search, read_package

SPEC = Path(os.environ.get("MOCA_SPEC_DIR") or Path(__file__).resolve().parents[2] / "moca-spec")
BASE = SPEC / "conformance" / "fixtures" / os.environ.get("MOCA_FUZZ_BASE", "structure-procedure")
FILES = {p.relative_to(BASE).as_posix(): p.read_bytes() for p in BASE.rglob("*") if p.is_file()}
PATHS = sorted(FILES)
LIMITS = {"maxEntries": 64, "maxBytes": 4 * 1024 * 1024}


class _Source:
    def __init__(self, target: str, data: bytes) -> None:
        self.target, self.data = target, data

    def list(self) -> list[str]:
        return PATHS

    def read(self, path: str) -> bytes:
        return self.data if path == self.target else FILES[path]


def fuzz(data: bytes) -> None:
    if not data:
        return
    # The first byte chooses the file to replace; the rest is its new content.
    target = PATHS[data[0] % len(PATHS)]
    pkg = read_package(_Source(target, data[1:]), limits=LIMITS)
    if not pkg.valid:
        return
    library = Library().add(pkg)
    Search(library, LexicalBackend(library), audiences=["public"]).search("module", limit=5)


if __name__ == "__main__":
    if not PATHS:
        sys.exit(f"no files under {BASE}: check out moca-spec beside this repository or set MOCA_SPEC_DIR")
    atheris.Setup(sys.argv, fuzz)
    atheris.Fuzz()
