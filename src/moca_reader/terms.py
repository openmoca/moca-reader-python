"""Creators' terms (package spec §4.14, Reader contract §15).

Terms are labels, not locks. The Reader exposes them exactly as written, works out who stated them (the authority),
and resolves and applies them only when the host asks: a search with a ``terms`` request. Nothing here fetches
anything, configures the Reader, or changes what a read or a search without a terms request returns.

A JSON value can be absent or ``null``, and the rules treat the two differently (package spec §4.14: absent means
not set; ``null`` is a value, and a malformed one). ``UNSET`` stands for absent throughout this module.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterable, Mapping
from typing import Any, Final

from ._js import js_sorted, js_string, truthy
from .schemas import schema_errors


class _Marker:
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return self.name


UNSET: Final = _Marker("UNSET")
"""An absent member: nothing sets the field."""
# Stands for a value under a container that is present and malformed: never a known value, so the strictest.
_MALFORMED: Final = _Marker("MALFORMED")

# The permission fields of `ai`, flattened. Each has an order from loosest to strictest.
FIELDS: Final[dict[str, tuple[Any, ...]]] = {
    "allowed.device": (True, False),
    "allowed.host": (True, False),
    "allowed.provider": (True, False),
    "allowed.training": (True, False),
    "allowed.machineTranslation": (True, False),
    "allowed.mention": (True, False),
    "answerSources": ("model", "work"),
}
# Contract §15.3: used only when no level sets a field.
PLATFORM: Final[dict[str, Any]] = {
    "allowed.device": True,
    "allowed.host": True,
    "allowed.provider": True,
    "allowed.training": False,
    "allowed.machineTranslation": True,
    "allowed.mention": True,
    "answerSources": "model",
}
# Contract §15.3 (moca-spec ADR-0041): fields with no node level. In a `nodes` entry they are U003 and have no effect.
PACKAGE_ONLY: Final = frozenset({"allowed.mention"})
_KNOWN_CONDITIONS: Final = frozenset({"noTraining", "noRetention"})
DESTINATIONS: Final = ("device", "host", "provider")
USES: Final = ("answer", "embed", "summarise", "train", "translate")
# The members of a rating request this version defines (contract §15.4).
_RATING_REQUEST: Final = frozenset({"explicit", "schemes", "allowUnrated", "acceptFeedRatings"})

Resolved = dict[str, Any]  # {"value": ..., "decidedBy": "platform" | "package" | "node" | "composite" | "host"}


def _member(obj: Any, key: str) -> Any:
    """``obj?.[key]`` in JavaScript: UNSET unless obj is an object holding key."""
    return obj[key] if isinstance(obj, dict) and key in obj else UNSET


def _same(a: Any, b: Any) -> bool:
    """JavaScript's SameValueZero for JSON values: True is not 1, and "1" is not 1."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and isinstance(a, str) and a == b


def _includes(values: Iterable[Any], value: Any) -> bool:
    return any(_same(v, value) for v in values)


# ----------------------------------------------------------------------------------------------------------------
# Checking (package spec §4.14)


def check_terms(terms: Any) -> list[dict[str, str]]:
    """Package spec §4.14: checks ``terms`` against the terms schema.

    Each problem is U003 (a string where only listed strings are allowed, or a member name the schema does not list)
    or U001 (anything else, and the checks the schema cannot express). Returns the problems, each
    ``{"code", "path", "message"}``. ``terms`` is UNSET when the manifest has none.
    """
    if terms is UNSET:
        return []
    problems: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(code: str, path: str, message: str) -> None:
        key = f"{code} {path}"
        if key in seen:
            return
        seen.add(key)
        problems.append({"code": code, "path": path, "message": message})

    for keyword, where, instance, subschema, message in schema_errors("terms", terms):
        base = ".".join(where)
        if keyword == "enum" and isinstance(instance, str):
            add("U003_TERMS_UNKNOWN_VALUE", base, f"{base} has a value this version does not know: {instance!r}")
        elif keyword == "additionalProperties":
            for name in _additional(instance, subschema):
                path = f"{base}.{name}" if base else name
                add("U003_TERMS_UNKNOWN_VALUE", path, f"{path} is a member this version does not know")
        else:
            add("U001_TERMS_INVALID", base or "(terms)", f"{base or 'terms'} {message}")

    nodes = _member(terms, "nodes")
    entries = list(enumerate(nodes)) if isinstance(nodes, list) else []
    ratings = [("rating", _member(terms, "rating")), *((f"nodes.{i}.rating", _member(n, "rating")) for i, n in entries)]
    for at, r in ratings:
        age = _member(r, "typicalAgeRange")
        bounds = re.fullmatch(r"([0-9]{1,2})-([0-9]{1,2})?", age) if isinstance(age, str) else None
        if bounds and bounds[2] is not None and int(bounds[1]) > int(bounds[2]):
            add(
                "U001_TERMS_INVALID",
                f"{at}.typicalAgeRange",
                f"{at}.typicalAgeRange has its lower bound above its upper",
            )
        listed = _member(r, "contentRating")
        if isinstance(listed, list):
            schemes = [s for x in listed if isinstance(s := _member(x, "scheme"), str)]
            if len(set(schemes)) != len(schemes):
                add("U001_TERMS_INVALID", f"{at}.contentRating", f"{at}.contentRating has two entries for one scheme")
    # A copyright year range must not end before it starts.
    copyrights = [
        ("rights.copyright", _member(_member(terms, "rights"), "copyright")),
        *((f"nodes.{i}.rights.copyright", _member(_member(n, "rights"), "copyright")) for i, n in entries),
    ]
    for at, c in copyrights:
        year = _member(c, "year")
        years = re.fullmatch(r"([0-9]{4})-([0-9]{4})", year) if isinstance(year, str) else None
        if years and int(years[1]) > int(years[2]):
            add("U001_TERMS_INVALID", f"{at}.year", f"{at}.year has its first year after its last")
    return problems


def _additional(instance: Any, subschema: Mapping[str, Any]) -> list[str]:
    """The member names an ``additionalProperties: false`` refuses, one problem each, as Ajv reports them."""
    if not isinstance(instance, dict):
        return []
    named = subschema.get("properties") or {}
    patterns = list((subschema.get("patternProperties") or {}).keys())
    return [k for k in instance if k not in named and not any(re.search(p, k) for p in patterns)]


# ----------------------------------------------------------------------------------------------------------------
# Resolving (contract §15.3)


def _ai_value(ai: Any, field: str) -> Any:
    """The value of a flattened field in an ``ai`` object; UNSET when nothing sets it. Contract §15.3: a container
    (``ai``, ``ai.allowed``) that is present and not an object makes every permission under it the strictest."""
    if ai is UNSET:
        return UNSET
    if not isinstance(ai, dict):
        return _MALFORMED
    if field.startswith("allowed."):
        allowed = _member(ai, "allowed")
        if allowed is UNSET:
            return UNSET
        return _member(allowed, field[8:]) if isinstance(allowed, dict) else _MALFORMED
    return _member(ai, field)


def _normalise(field: str, value: Any) -> Any:
    """A value a level sets, as one of the field's known values: a malformed or unknown value counts as the
    strictest."""
    if value is UNSET:
        return UNSET
    order = FIELDS[field]
    return next((v for v in order if _same(v, value)), order[-1])


def _conditions_of(ai: Any) -> list[str] | None:
    """The conditions a level sets; an unknown or malformed one is kept, so no host can meet it (the strictest)."""
    if ai is UNSET:
        return None
    if not isinstance(ai, dict):
        return ["(malformed)"]
    required = _member(ai, "providerRequires")
    if required is UNSET:
        return None
    if not isinstance(required, list):
        return ["(malformed)"]
    return [c if isinstance(c, str) and c in _KNOWN_CONDITIONS else f"(unknown:{js_string(c)})" for c in required]


def _stricter(field: str, a: Any, b: Any) -> bool:
    order = FIELDS[field]
    return order.index(a) > order.index(b)


def loosened_nodes(terms: Any) -> list[dict[str, str]]:
    """Contract §15.3 step 2, reported when the package is read: a ``nodes`` entry whose ``ai`` value is looser
    than the package's own. One finding per entry and field, each ``{"path", "message"}``."""
    out: list[dict[str, str]] = []
    nodes = _member(terms, "nodes")
    if not isinstance(nodes, list):
        return out
    package_ai = _member(terms, "ai")
    for i, entry in enumerate(nodes):
        entry_ai = _member(entry, "ai")
        for field in FIELDS:
            if field in PACKAGE_ONLY:
                continue
            pkg = _normalise(field, _ai_value(package_ai, field))
            node = _normalise(field, _ai_value(entry_ai, field))
            if pkg is not UNSET and node is not UNSET and _stricter(field, pkg, node):
                out.append(
                    {
                        "path": f"nodes.{i}.ai.{field}",
                        "message": f"nodes[{i}] sets {field} {js_string(node)}, looser than the package's "
                        f"{js_string(pkg)}; the package's value stands",
                    }
                )
        pc = _conditions_of(package_ai)
        nc = _conditions_of(entry_ai)
        if pc is not None and nc is not None and any(c not in nc for c in pc):
            out.append(
                {
                    "path": f"nodes.{i}.ai.providerRequires",
                    "message": f"nodes[{i}] drops provider conditions the package sets; the package's stand",
                }
            )
    return out


def authority_of(signers: list[str]) -> str:
    """Contract §15.2: from the package's valid package attestations, never from fields the signer writes:
    ``packager`` when one verifies under the host's trust root, otherwise ``unverified``."""
    return "packager" if signers else "unverified"


# The entry every node gets when `nodes`, or one of its entries, cannot be read: everything at its strictest.
_STRICTEST_ENTRY: Final[dict[str, Any]] = {"ai": None, "rating": False}


def _well_formed_entry(entry: Any) -> bool:
    paths = _member(entry, "paths")
    return isinstance(paths, list) and all(isinstance(p, str) for p in paths)


def node_entry(terms: Any, path: str) -> dict[str, Any] | None:
    """The ``nodes`` entry that applies to a node path: the longest matching path or ``/``-ended prefix (package
    spec §4.14). Contract §15.3: a ``nodes`` that is present and not a list, an entry that is not an object, and an
    entry whose ``paths`` is not a list of strings do not say which nodes they mean, so they count for every node,
    at the strictest."""
    nodes = _member(terms, "nodes")
    if nodes is UNSET:
        return None
    if not isinstance(nodes, list) or not all(_well_formed_entry(e) for e in nodes):
        return _STRICTEST_ENTRY
    full = f"content/{path}"
    best: dict[str, Any] | None = None
    best_length = -1
    for entry in nodes:
        for p in entry["paths"]:
            hit = full.startswith(p) if p.endswith("/") else full == p
            if hit and len(p) > best_length:
                best, best_length = entry, len(p)
    return best


def resolve_ai(
    pkg: Mapping[str, Any],
    path: str | None,
    limits: Any = UNSET,
    composites: Iterable[Any] = (),
) -> dict[str, Resolved]:
    """Contract §15.3: the resolved ``ai`` terms for one node, each field ``{"value", "decidedBy"}``;
    ``providerRequires`` is a list of conditions.

    ``pkg`` is ``{"terms", "authority"}``; ``path`` the node path under content/, or None for the package-level
    terms, with no node level (contract §15.4, "Closed and hidden"); ``limits`` the host's terms limits (an ``ai`` object: floors, never
    values); ``composites`` the ``terms`` of composing packages whose signers speak for this package (step 3).
    """
    terms = pkg.get("terms")
    terms = terms if terms is not None else {}
    composites = list(composites)
    node = node_entry(terms, path) if path is not None else None
    terms_ai = _member(terms, "ai")
    node_ai = _member(node, "ai")
    out: dict[str, Resolved] = {}
    levels = [(terms_ai, "package"), (node_ai, "node"), *((_member(c, "ai"), "composite") for c in composites)]
    levels.append((limits, "host"))
    for field in FIELDS:
        value, decided_by = PLATFORM[field], "platform"
        # Each level applies only if it is as strict or stricter: no authority in this version lets a package
        # loosen the platform.
        for ai, level in levels:
            # A package-level field has no node level, even under a malformed entry (contract §15.3).
            if level == "node" and field in PACKAGE_ONLY:
                continue
            n = _normalise(field, _ai_value(ai, field))
            if n is not UNSET and (_stricter(field, n, value) or n == value):
                value, decided_by = n, level
        out[field] = {"value": value, "decidedBy": decided_by}
    conditions: list[str] = []
    decided = "platform"
    for ai, level in levels:
        found = _conditions_of(ai)
        if found is None:
            continue
        merged = list(dict.fromkeys([*conditions, *found]))
        if len(merged) > len(conditions):
            decided = level
        conditions = merged
    out["providerRequires"] = {"value": js_sorted(conditions), "decidedBy": decided}
    return out


def rating_of(terms: Any, path: str) -> Any:
    """The node's effective rating as written: its own ``nodes`` entry's, if any, else the package's (contract
    §15.3); None when neither sets one. A rating that is present and not an object is returned as it is (``null``
    as False): the gate counts it as the strictest rating."""
    node = node_entry(terms, path)
    own = _member(node, "rating")
    if own is UNSET:
        own = _member(terms, "rating")
    if own is UNSET:
        return None
    return False if own is None else own


def _destination_of(wanted: Any) -> str:
    """The destination a request's ``ai`` part names; an unknown or missing one is treated as the strictest,
    provider."""
    destination = _member(wanted, "destination")
    return destination if isinstance(destination, str) and destination in DESTINATIONS else "provider"


def _conditions_met(wanted: Any) -> set[str]:
    listed = _member(wanted, "conditions")
    return set(c for c in listed if isinstance(c, str)) if isinstance(listed, list) else set()


def closure_of(request: Any, ai: Mapping[str, Resolved]) -> dict[str, Any]:
    """Contract §15.4, "Closed and hidden": whether a package is closed for a request's ``ai`` part, from its
    package-level resolved terms (``resolve_ai`` with no path), and whether it is hidden. A use never closes a
    package. Returns ``{"closed", "closedBy", "hidden"}``."""
    wanted = _member(request, "ai")
    # As in JavaScript, any object (an array too) is an `ai` part; anything else closes nothing.
    if not isinstance(wanted, (dict, list)):
        return {"closed": False, "closedBy": [], "hidden": False}
    destination = _destination_of(wanted)
    closed_by: list[str] = []
    if ai[f"allowed.{destination}"]["value"] is not True:
        closed_by.append(f"ai.allowed.{destination}")
    elif destination == "provider" and any(c not in _conditions_met(wanted) for c in ai["providerRequires"]["value"]):
        closed_by.append("ai.providerRequires")
    closed = bool(closed_by)
    return {"closed": closed, "closedBy": closed_by, "hidden": closed and ai["allowed.mention"]["value"] is not True}


def gate_reasons(request: Mapping[str, Any], ai: Mapping[str, Resolved], rating: Any) -> list[str]:
    """Contract §15.4: the reasons the terms gate removes a record, or an empty list. ``ai`` is the node's resolved
    terms; ``rating`` its effective rating (``rating_of``)."""
    reasons: list[str] = []
    wanted = request.get("ai")
    if truthy(wanted):
        destination = _destination_of(wanted)
        conditions = _conditions_met(wanted)
        if ai[f"allowed.{destination}"]["value"] is not True:
            reasons.append(f"ai.allowed.{destination}")
        elif destination == "provider" and any(c not in conditions for c in ai["providerRequires"]["value"]):
            reasons.append("ai.providerRequires")
        use = _member(wanted, "use")
        if use == "train" and ai["allowed.training"]["value"] is not True:
            reasons.append("ai.allowed.training")
        if use == "translate" and ai["allowed.machineTranslation"]["value"] is not True:
            reasons.append("ai.allowed.machineTranslation")
    if "rating" in request:
        r = request["rating"]
        # A request this version cannot honour in full is never run as a weaker one: it removes every record.
        schemes = _member(r, "schemes")
        if (
            not isinstance(r, dict)
            or any(k not in _RATING_REQUEST for k in r)
            or (schemes is not UNSET and not isinstance(schemes, dict))
        ):
            reasons.append("rating.request")
            return reasons
        # A rating that is present and malformed counts as the strictest: explicit, and outside every listed scheme.
        malformed = rating is not None and not isinstance(rating, dict)
        from_feed = not malformed and _member(rating, "declaredBy") == "feed"
        explicit: bool | None = None
        if malformed:
            explicit = True
        elif rating is not None and "explicit" in rating:
            explicit = rating["explicit"] if isinstance(rating["explicit"], bool) else True
            # A feed's `explicit: false` counts only when the host accepts feed ratings; otherwise it is unrated.
            if from_feed and explicit is False and r.get("acceptFeedRatings") is not True:
                explicit = None
        found = _member(rating, "contentRating") if not malformed else UNSET
        entries: Any = [] if found is UNSET else found
        unreadable = (
            malformed
            or not isinstance(entries, list)
            or any(not isinstance(x, dict) or not isinstance(x.get("scheme"), str) for x in entries)
        )
        # Only the schemes the host listed count: a rating under any other scheme says nothing to this filter.
        host_schemes = schemes if isinstance(schemes, dict) else {}
        considered = [
            (scheme, allowed)
            for scheme, allowed in _js_entries(host_schemes)
            if unreadable or any(x["scheme"] == scheme for x in entries)
        ]
        if explicit is None and not considered:
            if r.get("allowUnrated") is not True:
                reasons.append("rating.unrated")
        else:
            if r.get("explicit") is False and explicit is True:
                reasons.append("rating.explicit")
            for scheme, allowed in considered:
                entry = None if unreadable else next((x for x in entries if x["scheme"] == scheme), None)
                if entry is None or not isinstance(allowed, list) or not _includes(allowed, _member(entry, "value")):
                    reasons.append(f"rating.{scheme}")
    return reasons


def _js_entries(obj: dict[str, Any]) -> list[tuple[str, Any]]:
    """``Object.entries``: integer-like keys first, in ascending order, then the rest in insertion order."""
    index = [k for k in obj if re.fullmatch(r"0|[1-9][0-9]*", k) and int(k) < 2**32 - 1]
    rest = [k for k in obj if k not in index]
    return [(k, obj[k]) for k in [*sorted(index, key=int), *rest]]


def resolve_export(pkg: Mapping[str, Any], composites: Iterable[Any] = ()) -> Resolved:
    """Contract §15.3: the resolved export permission (``rights.export.allowed``). Only the package, and a composing
    package whose signers speak for the member, set it; the platform default is true, and a malformed value counts
    as false."""
    value, decided_by = True, "platform"

    def apply(terms: Any, level: str) -> None:
        nonlocal value, decided_by
        # A `rights` or `rights.export` that is present and not an object counts as the strictest: not allowed.
        rights = _member(terms, "rights")
        if rights is UNSET:
            return
        if not isinstance(rights, dict):
            v: Any = _MALFORMED
        else:
            export = _member(rights, "export")
            if export is UNSET:
                return
            v = _member(export, "allowed") if isinstance(export, dict) else _MALFORMED
        if v is UNSET:
            return
        n = v is True
        # As strict or stricter applies.
        if not n or value:
            value, decided_by = n, level

    apply(pkg.get("terms"), "package")
    for c in composites:
        apply(c, "composite")
    return {"value": value, "decidedBy": decided_by}


def _clean(problems: Iterable[Mapping[str, str]], path: str) -> bool:
    """Is a terms field usable: no problem at its path or under it (contract §7)?"""
    return not any(p["path"] == path or p["path"].startswith(f"{path}.") for p in problems)


def rights_of(terms: Any, problems: list[dict[str, str]] | None, license: Any, path: str) -> dict[str, Any]:
    """Contract §7: a node's licence and copyright statement. The node's ``terms.nodes`` entry first, else the
    package's (``license`` from the manifest, ``terms.rights.copyright``); a value with a terms problem at or under
    its path is skipped.

    ``terms`` is the declared terms (UNSET or None when there are none); ``license`` the manifest's, when the
    manifest passes its schema; ``path`` the node path under content/.
    """
    found = problems or []
    entry = node_entry(terms, path)
    at = None
    if entry is not None and entry is not _STRICTEST_ENTRY:
        index = next(i for i, e in enumerate(terms["nodes"]) if e is entry)
        at = f"nodes.{index}.rights"
    own = _member(entry, "rights") if at else UNSET
    out: dict[str, Any] = {}
    own_license = _member(own, "license")
    if at and isinstance(own_license, str) and _clean(found, f"{at}.license"):
        out["license"] = own_license
    elif isinstance(license, str):
        out["license"] = license
    own_copyright = _member(own, "copyright")
    package_copyright = _member(_member(terms, "rights"), "copyright")
    if at and isinstance(own_copyright, (dict, list)) and _clean(found, f"{at}.copyright"):
        out["copyright"] = copy.deepcopy(own_copyright)
    elif isinstance(package_copyright, (dict, list)) and _clean(found, "rights.copyright"):
        out["copyright"] = copy.deepcopy(package_copyright)
    return out


def record_terms(authority: Any, ai: Mapping[str, Resolved], rating: Any, export: Resolved | None) -> dict[str, Any]:
    """The ``terms`` field of a citation record from a search with a terms request (citation-record schema)."""
    nested: dict[str, Any] = {"allowed": {}}
    for k, v in ai.items():
        if k.startswith("allowed."):
            nested["allowed"][k[8:]] = v
        else:
            nested[k] = v
    out: dict[str, Any] = {"authority": authority, "ai": nested}
    # A rating that is present and not an object is shown as what it counts as: explicit.
    if rating is not None:
        out["rating"] = rating if isinstance(rating, dict) else {"explicit": True}
    if export is not None:
        out["rights"] = {"export": export}
    return out


def terms_request(
    destination: str = "provider",
    conditions: Iterable[str] | None = None,
    terms: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """A terms request (contract §15.4) for an app that hands records to a model: ``ai`` with the destination the
    app declares (``provider``, a third party's model, unless it declares ``device`` or ``host``) and the provider
    conditions it meets, plus anything else in ``terms`` (a ``rating`` request, say). An ``ai`` in ``terms`` is used
    as it is, and must be an object: a binding a model calls never hands content on without an ``ai`` part (contract
    §15.4), so ``destination`` is the way to choose where the model runs. Used by the framework bindings, which apply
    it to every search."""
    if destination not in DESTINATIONS:
        raise ValueError(f"destination must be one of {', '.join(DESTINATIONS)}, not {destination!r}")
    if terms is not None and "ai" in terms and not isinstance(terms["ai"], dict):
        raise ValueError("terms['ai'] must be an object; set destination to choose where the model runs")
    request = copy.deepcopy(dict(terms or {}))
    listed = list(conditions or [])
    request.setdefault("ai", {"destination": destination, **({"conditions": listed} if listed else {})})
    return request


def ingest_terms(destination: str = "provider", conditions: Iterable[str] | None = None) -> dict[str, Any]:
    """An ingest's terms request (contract §9.4): ``{"destination", "conditions"}``, where the host's embedder runs
    (``provider``, a third party's model, unless it declares ``device`` or ``host``) and the provider conditions it
    meets. Used by the framework bindings, which pass it to every ingest."""
    if destination not in DESTINATIONS:
        raise ValueError(f"destination must be one of {', '.join(DESTINATIONS)}, not {destination!r}")
    return {"destination": destination, "conditions": list(conditions or [])}
