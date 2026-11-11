"""Citation records and the default retrieval policy (Reader contract §7 and §8).

A citation record is a dict valid against citation-record.schema.json: the same JSON in every Reader.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ._js import effective_window, get, js_string, timestamp, truthy
from .audience import audience_of
from .content import ContentNode, Representation
from .digest import utf8
from .reviews import review_status_of

if TYPE_CHECKING:
    from .reader import PackageResult

CitationRecord = dict[str, Any]
RelationIndex = tuple[dict[str, list[str]], dict[str, list[str]]]  # superseded, contested


def passes_default_policy(record: CitationRecord) -> bool:
    """In force, not superseded, not deprecated (Reader contract §8)."""
    trust = record["trust"]
    return bool(trust.get("inForce")) and not trust.get("superseded") and trust.get("status") != "deprecated"


def pick_representation(node: ContentNode, locale: str | None) -> Representation:
    """The representation package spec §5 selects for a locale: exact, then a parent, then a child, then the default."""
    if not locale:
        return node.representations[0]
    want = locale.lower()
    reps = node.representations
    # Package spec §5.4: exact; then the longest tag the request starts with (RFC 4647 Lookup); then the lowest
    # tag, in code-point order, that starts with the request.
    tagged = [r for r in reps if r.locale]
    parents = sorted(
        (r for r in tagged if want.startswith(f"{(r.locale or '').lower()}-")), key=lambda r: -len(r.locale or "")
    )
    children = sorted(
        (r for r in tagged if (r.locale or "").lower().startswith(f"{want}-")), key=lambda r: r.locale or ""
    )
    return (
        next((r for r in tagged if (r.locale or "").lower() == want), None)
        or (parents[0] if parents else None)
        or (children[0] if children else None)
        or reps[0]
    )


def _declared(value: Any) -> dict[str, str]:
    out = {"by": js_string(value.get("by"), "by" in value) if isinstance(value, dict) else "undefined"}
    at = get(value, "at")
    if truthy(at):
        out["at"] = js_string(at)
    return out


def _date_or_none(value: Any) -> Any:
    """A frontmatter or manifest date that parses, or None."""
    if value is None or value == "":
        return None
    return None if math.isnan(timestamp(value)) else value


def _has_actor(entry: Any) -> bool:
    """An OKF ``generated`` or ``verified`` entry that names its actor."""
    return isinstance(entry, dict) and entry.get("by") is not None and js_string(entry["by"]) != ""


def citation_for(
    result: PackageResult,
    node: ContentNode,
    rep: Representation,
    now: datetime | None = None,
    index: RelationIndex | None = None,
    text: str | None = None,
) -> CitationRecord:
    """Builds one citation record."""
    manifest = result.manifest
    fm = rep.frontmatter
    moca = fm["moca"] if isinstance(fm.get("moca"), (dict, list)) else {}
    moca = moca if isinstance(moca, dict) else {}
    key = f"{js_string(manifest.get('id'))}@{js_string(manifest.get('version'))}"
    # Package spec §4.4: the node's window is the intersection of the package's and its own. A bound that does not
    # parse, or a window whose end is not after its start, is ignored: it never takes a node out of force.
    valid_from, valid_until, from_at, until_at = effective_window(
        manifest.get("validFrom"), manifest.get("validUntil"), moca.get("valid_from"), moca.get("valid_until")
    )
    t = (now or datetime.now(UTC)).timestamp() * 1000
    superseded_by = list(index[0].get(key, [])) if index else []
    contested_by = [
        *(moca["contested_by"] if isinstance(moca.get("contested_by"), list) else []),
        *(index[1].get(key, []) if index else []),
    ]
    declared_sources = fm.get("sources")
    sources: dict[Any, Any] = {}
    for s in declared_sources if isinstance(declared_sources, list) else []:
        sid = get(s, "id")
        if truthy(sid) and isinstance(sid, (str, int, float, bool)):
            sources[sid] = s

    package: dict[str, Any] = {
        "id": manifest.get("id"),
        "version": manifest.get("version"),
        "digest": result.digest,
        "signed": len(result.signers) > 0,
    }
    if result.signers:
        package["signers"] = list(result.signers)

    node_part: dict[str, Any] = {
        "id": f"{js_string(manifest.get('id'))}#{node.path}",
        "ref": f"{key}#{node.path}",
        "path": node.path,
    }
    if rep.locale:
        node_part["locale"] = rep.locale
    elif truthy(manifest.get("language")):
        node_part["locale"] = manifest["language"]
    node_part["type"] = fm.get("type")
    if isinstance(fm.get("title"), str):
        node_part["title"] = fm["title"]
    if isinstance(fm.get("description"), str):
        node_part["description"] = fm["description"]
    if isinstance(fm.get("tags"), list):
        node_part["tags"] = [x for x in fm["tags"] if isinstance(x, str)]
    if rep.sha256:
        node_part["digest"] = f"sha256:{rep.sha256}"

    verified = fm.get("verified")
    verified_list = verified if isinstance(verified, list) else [verified] if truthy(verified) else []
    generated = fm.get("generated")
    trust: dict[str, Any] = {
        "status": fm["status"] if fm.get("status") in ("draft", "stable", "deprecated") else "stable",
        # An entry with no actor (`by`) is dropped rather than reported as "undefined".
        "generated": _declared(generated) if _has_actor(generated) else None,
        "declaredVerified": [_declared(v) for v in verified_list if _has_actor(v)],
        "attestedReviews": [
            {**_review_json(r), "packageVerified": bool(result.signers)}
            for r in result.reviews_by_file.get(rep.file, [])
        ],
        "reviewStatus": review_status_of(result.reviews_by_file.get(rep.file), bool(result.signers)),
    }
    stale_after = _date_or_none(fm.get("stale_after"))
    if truthy(stale_after):
        trust["staleAfter"] = js_string(stale_after)
    if truthy(valid_from):
        trust["validFrom"] = js_string(valid_from)
    if truthy(valid_until):
        trust["validUntil"] = js_string(valid_until)
    trust["stale"] = t >= timestamp(stale_after) if truthy(stale_after) else False
    trust["inForce"] = (from_at is None or t >= from_at.timestamp() * 1000) and (
        until_at is None or t < until_at.timestamp() * 1000
    )
    trust["superseded"] = len(superseded_by) > 0
    if superseded_by:
        trust["supersededBy"] = superseded_by
    trust["contested"] = len(contested_by) > 0
    if contested_by:
        trust["contestedBy"] = contested_by

    evidence: list[dict[str, Any]] = []
    for i, e in enumerate(moca["evidence"] if isinstance(moca.get("evidence"), list) else []):
        if not truthy(e) or not isinstance(e, (dict, list)):
            continue
        source_key = get(e, "source")
        hashable = isinstance(source_key, (str, int, float, bool))
        if hashable and source_key in sources:
            source = sources[source_key]
        else:
            source = {"id": source_key} if isinstance(e, dict) and "source" in e else {}
        entry: dict[str, Any] = {"source": source}
        if truthy(get(e, "selector")):
            entry["selector"] = get(e, "selector")
        if truthy(get(e, "note")):
            entry["note"] = get(e, "note")
        matched = rep.evidence_checks[i].matched if i < len(rep.evidence_checks) else None
        if matched is not None:
            entry["matched"] = matched
        evidence.append(entry)

    record: CitationRecord = {
        "package": package,
        "node": node_part,
        "span": {"start": rep.body_offset, "end": rep.body_offset + len(utf8(rep.body))},
        "trust": trust,
        "evidence": evidence,
    }
    if rep.concepts:
        record["concepts"] = list(rep.concepts)
    label, invalid = audience_of(node, rep)
    if label is not None:
        record["audience"] = label
    if invalid:
        record["audienceInvalid"] = True
    if result.profiles:
        record["profiles"] = list(result.profiles)
    if text is not None:
        record["text"] = text
    return record


def _review_json(review: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"reviewer": review.reviewer, "reviewedAt": review.reviewed_at, "outcome": review.outcome}
    if review.signer is not None:
        out["signer"] = review.signer
    if review.scope is not None:
        out["scope"] = review.scope
    return out
