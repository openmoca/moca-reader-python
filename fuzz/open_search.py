"""Fuzz target: open an untrusted archive and search it (moca-spec SECURITY.md, "Archive handling in the Readers").

Atheris calls ``fuzz()`` with mutated bytes, seeded from the conformance corpus (seed.py). A package is untrusted
input, so ``read_package`` must never raise, and a package it reads as valid must be searchable without raising.

Usage: python fuzz/open_search.py <corpus dirs> [libFuzzer options]
"""

import sys

import atheris

with atheris.instrument_imports(include=["moca_reader"]):
    from moca_reader import LexicalBackend, Library, Search, read_package

LIMITS = {"maxEntries": 512, "maxBytes": 8 * 1024 * 1024}
QUERIES = ("refund", "the", "a b c")


def fuzz(data: bytes) -> None:
    pkg = read_package(data, limits=LIMITS)
    if not pkg.valid:
        return
    library = Library().add(pkg)
    search = Search(library, LexicalBackend(library), audiences=["public"])
    for query in QUERIES:
        search.search(query, limit=5)


if __name__ == "__main__":
    atheris.Setup(sys.argv, fuzz)
    atheris.Fuzz()
