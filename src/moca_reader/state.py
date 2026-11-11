"""Package states (Reader contract §9.4): what a store search needs, per package, to recompute every field of a
stored citation record that depends on the library or the trust root, without loading the package."""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any

from ._js import timestamp
from .relations import relation_index_of
from .reviews import review_status_of

if TYPE_CHECKING:
    from .reader import PackageResult


class _Review:
    def __init__(self, outcome: str) -> None:
        self.outcome = outcome


def package_state(result: PackageResult) -> dict[str, Any]:
    """A package's state, as plain JSON a host can keep beside its store."""
    contests: dict[str, list[Any]] = {}
    for node in result.nodes:
        for rep in node.representations:
            moca = rep.frontmatter.get("moca")
            listed = moca.get("contested_by") if isinstance(moca, dict) else None
            if isinstance(listed, list) and listed:
                contests[rep.file] = list(listed)
    reviews = {
        path: [
            {
                "reviewer": r.reviewer,
                "reviewedAt": r.reviewed_at,
                "outcome": r.outcome,
                **({"signer": r.signer} if r.signer is not None else {}),
                **({"scope": r.scope} if r.scope is not None else {}),
            }
            for r in entries
        ]
        for path, entries in result.reviews_by_file.items()
    }
    manifest = result.manifest
    state: dict[str, Any] = {"digest": result.digest, "id": manifest.get("id"), "version": manifest.get("version")}
    if isinstance(manifest.get("language"), str):
        state["language"] = manifest["language"]
    state.update(
        {
            "relations": manifest.get("relations") if isinstance(manifest.get("relations"), list) else [],
            "relationScopes": list(result.relation_scopes),
            "signers": list(result.signers),
            "reviews": reviews,
            "contests": contests,
        }
    )
    return state


def _file_of(record: dict[str, Any], state: dict[str, Any]) -> str:
    path, locale = record["node"]["path"], record["node"].get("locale")
    if not locale or locale == state.get("language"):
        return f"content/{path}"
    stem = re.sub(r"(?ai)\.md\Z", "", path)
    return f"content/{stem}.{locale}.md"


def state_index(
    states: dict[str, dict[str, Any]], allow_unsigned_relations: bool = False
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """The relation index over a set of package states."""
    return relation_index_of(list(states.values()), allow_unsigned_relations)


def refresh_record(
    record: dict[str, Any],
    now: datetime,
    states: dict[str, dict[str, Any]],
    index: tuple[dict[str, list[str]], dict[str, list[str]]],
) -> dict[str, Any] | None:
    """A stored record with every library- and trust-dependent field recomputed; None when its package is not
    among the states."""
    state = states.get(record.get("package", {}).get("digest"))
    if state is None:
        return None
    t = now.timestamp() * 1000
    trust = dict(record["trust"])

    def at(value: Any) -> float:
        v = timestamp(value)
        return v if not math.isnan(v) else math.nan

    trust["stale"] = t >= at(trust["staleAfter"]) if trust.get("staleAfter") else False
    trust["inForce"] = (not trust.get("validFrom") or t >= at(trust["validFrom"])) and (
        not trust.get("validUntil") or t < at(trust["validUntil"])
    )
    key = f"{state['id']}@{state['version']}"
    file = _file_of(record, state)
    superseded_by = index[0].get(key, [])
    contested_by = [*(state.get("contests") or {}).get(file, []), *index[1].get(key, [])]
    trust["superseded"] = bool(superseded_by)
    trust.pop("supersededBy", None)
    if superseded_by:
        trust["supersededBy"] = list(superseded_by)
    trust["contested"] = bool(contested_by)
    trust.pop("contestedBy", None)
    if contested_by:
        trust["contestedBy"] = contested_by
    signed = bool(state.get("signers"))
    reviews = (state.get("reviews") or {}).get(file, [])
    trust["attestedReviews"] = [{**r, "packageVerified": signed} for r in reviews]
    trust["reviewStatus"] = review_status_of([_Review(r["outcome"]) for r in reviews], signed)
    package = {**record["package"], "signed": signed}
    package.pop("signers", None)
    if signed:
        package["signers"] = list(state["signers"])
    return {**record, "package": package, "trust": trust}
