"""A simple host resolver for members: looks for packages in a list of directories. Hosts with a registry
supply their own resolver instead."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from typing import Any


def directory_resolver(dirs: Iterable[str | os.PathLike[str]]) -> Callable[[dict[str, Any]], str | None]:
    """A ``resolve_member`` that finds ``{id, version}`` among the package directories in, or equal to, each directory."""
    candidates: list[tuple[Any, Any, str]] = []
    for d in [os.fspath(x) for x in dirs]:
        if not os.path.exists(d):
            continue
        roots = [d, *(os.path.join(d, n) for n in os.listdir(d) if os.path.isdir(os.path.join(d, n)))]
        for root in roots:
            manifest = os.path.join(root, "moca.json")
            if not os.path.exists(manifest):
                continue
            try:
                with open(manifest, encoding="utf-8") as f:
                    m = json.load(f)
                candidates.append((m.get("id"), m.get("version"), root))
            except (ValueError, OSError, AttributeError):
                continue  # an unreadable manifest is not a candidate

    def resolve(member: dict[str, Any]) -> str | None:
        return next((root for i, v, root in candidates if i == member.get("id") and v == member.get("version")), None)

    return resolve
