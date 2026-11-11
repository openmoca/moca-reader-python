"""Package-level relation effects (package spec §7.2) over a set of packages: loaded results in a Library, or
package states for a store search (Reader contract §9.4)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ._js import get, js_string, truthy
from .attestations import scope_covers


def relation_index_of(
    packages: Sequence[dict[str, Any]], allow_unsigned_relations: bool = False
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """(superseded, contested), each keyed by ``id@version``. Each package is ``{id, version, relations,
    relationScopes}``."""
    superseded: dict[str, list[str]] = {}
    contested: dict[str, list[str]] = {}

    def push(table: dict[str, list[str]], key: str, value: str) -> None:
        values = table.setdefault(key, [])
        if value not in values:
            values.append(value)

    for m in packages:
        relations = m.get("relations")
        for r in relations if isinstance(relations, list) else []:
            # Package spec §7.2: only relations a signer of the package may make take effect.
            if not allow_unsigned_relations and not scope_covers(m.get("relationScopes") or [], get(r, "target")):
                continue
            targets = [
                t
                for t in packages
                if t.get("id") == get(r, "target")
                and (not truthy(get(r, "version")) or t.get("version") == r["version"])
            ]
            for t in targets:
                key = f"{js_string(t.get('id'))}@{js_string(t.get('version'))}"
                own = f"{js_string(m.get('id'))}@{js_string(m.get('version'))}"
                if get(r, "type") == "supersedes":
                    push(superseded, key, own)
                if get(r, "type") == "conflictsWith":
                    push(contested, key, own)
                    push(contested, own, key)
    return superseded, contested
