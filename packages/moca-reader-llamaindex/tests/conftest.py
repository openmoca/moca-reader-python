"""Fixtures over moca-spec's support-kb: ``MOCA_SPEC_DIR``, else ``moca-spec`` beside this repository."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from moca_reader import LexicalBackend, Library, Search, read_package

REPO = Path(__file__).resolve().parents[3]
MOCA_SPEC = Path(os.environ.get("MOCA_SPEC_DIR") or REPO.parent / "moca-spec").resolve()


@pytest.fixture
def moca_spec() -> Path:
    return MOCA_SPEC


@pytest.fixture
def library() -> Library:
    pkg = read_package(
        MOCA_SPEC / "examples" / "support-kb", trust_root=MOCA_SPEC / "fixtures" / "signing-keys" / "trust-root.json"
    )
    return Library().add(pkg)


@pytest.fixture
def public_search(library: Library) -> Search:
    return Search(library, LexicalBackend(library), audiences=["public"])
