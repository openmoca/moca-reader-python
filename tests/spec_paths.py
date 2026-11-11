"""Finds the moca-spec checkout: ``MOCA_SPEC_DIR``, else ``../moca-spec`` beside this repository."""

from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MOCA_SPEC = Path(os.environ.get("MOCA_SPEC_DIR") or REPO.parent / "moca-spec").resolve()
EXAMPLES = MOCA_SPEC / "examples"

if not (MOCA_SPEC / "conformance" / "cases.json").exists():
    raise RuntimeError("Cannot find moca-spec. Clone it beside this repository or set MOCA_SPEC_DIR.")
