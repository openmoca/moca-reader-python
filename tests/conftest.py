"""Makes tests/spec_paths.py importable by the tests beside it."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
