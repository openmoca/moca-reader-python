"""YAML frontmatter for OKF concept documents.

Parsed with the YAML 1.2 core schema (package spec §5): timestamps, ``yes``, ``no`` and ``on`` stay strings
exactly as written, and aliases are refused (Reader contract §3). PyYAML's own resolvers follow YAML 1.1, so
this reads PyYAML's event stream and resolves plain scalars itself, as the .NET Reader does.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

import yaml

from ._js import js_trim, number_to_string
from .digest import utf8

_OPEN = re.compile(r"^---[ \t]*\r?\n")
# Package spec §5.1: only LF ends a line (CRLF is LF after CR).
_CLOSE = re.compile(r"(?:^|(?<=\n))---[ \t]*(?:\r?\n|\Z)")


@dataclass
class FrontmatterSplit:
    present: bool
    body: str
    body_offset: int
    line: int = 1
    raw: str | None = None
    data: Any = None
    error: str | None = None


def split_frontmatter(text: str, max_bytes: float = math.inf) -> FrontmatterSplit:
    """Splits a document into frontmatter and body; ``body_offset`` is the UTF-8 byte offset of the body."""
    bom = "\ufeff" if text.startswith("\ufeff") else ""
    rest = text[len(bom) :]
    opened = _OPEN.match(rest)
    if not opened:
        return FrontmatterSplit(False, text, len(utf8(bom)))
    after_open = rest[opened.end() :]
    closed = _CLOSE.search(after_open)
    if not closed:
        return FrontmatterSplit(True, text, 0, error="frontmatter block is not closed with ---")
    raw = after_open[: closed.start()]
    consumed = bom + opened.group(0) + after_open[: closed.end()]
    result = FrontmatterSplit(True, text[len(consumed) :], len(utf8(consumed)), raw=raw)
    if len(utf8(raw)) > max_bytes:
        result.error = f"frontmatter is larger than the {int(max_bytes)}-byte limit"
        return result
    try:
        result.data = {} if js_trim(raw) == "" else load_core_schema(raw)
    except yaml.YAMLError as err:
        mark = getattr(err, "problem_mark", None) or getattr(err, "context_mark", None)
        result.error = str(getattr(err, "problem", None) or err)
        if mark is not None:
            result.line = mark.line + 2
        return result
    if not isinstance(result.data, dict):
        result.error = "frontmatter is not a YAML mapping"
    return result


_NULL = re.compile(r"^(?:null|Null|NULL|~)?\Z")
_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)\Z")
_INT = re.compile(r"^[-+]?[0-9]+\Z")
_OCT = re.compile(r"^0o[0-7]+\Z")
_HEX = re.compile(r"^0x[0-9a-fA-F]+\Z")
_FLOAT = re.compile(r"^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?\Z")
_STR_TAG = "tag:yaml.org,2002:str"


class _Error(yaml.MarkedYAMLError):
    pass


def _error(message: str, event: Any) -> _Error:
    """An error at an event, with its position, for C002's line number."""
    return _Error(None, None, message, event.start_mark)


def _resolve(event: yaml.ScalarEvent) -> Any:
    value = event.value
    # Quoted and block scalars, and explicitly tagged strings, are always strings.
    if event.style is not None or event.tag in (_STR_TAG, "!"):
        return value
    if _NULL.match(value):
        return None
    if _BOOL.match(value):
        return value.lower() == "true"
    if _INT.match(value):
        return int(value)
    if _OCT.match(value):
        return int(value[2:], 8)
    if _HEX.match(value):
        return int(value[2:], 16)
    if _FLOAT.match(value):
        return float(value)
    return value


def _key_text(key: Any) -> str:
    if key is None:
        return "null"
    if isinstance(key, str):
        return key
    return number_to_string(key)


def load_core_schema(text: str) -> Any:
    """Loads one YAML document with the YAML 1.2 core schema; aliases and duplicate keys are errors."""
    events = iter(yaml.parse(text, Loader=yaml.SafeLoader))

    def node(event: yaml.Event) -> Any:
        if isinstance(event, yaml.AliasEvent):
            # Alias expansion is a denial-of-service vector (Reader contract §3, "YAML aliases in frontmatter: 0").
            raise _error("YAML aliases are not allowed in frontmatter", event)
        if isinstance(event, yaml.ScalarEvent):
            return _resolve(event)
        if isinstance(event, yaml.SequenceStartEvent):
            out: list[Any] = []
            for e in events:
                if isinstance(e, yaml.SequenceEndEvent):
                    return out
                out.append(node(e))
        if isinstance(event, yaml.MappingStartEvent):
            mapping: dict[str, Any] = {}
            for e in events:
                if isinstance(e, yaml.MappingEndEvent):
                    return mapping
                if not isinstance(e, yaml.ScalarEvent):
                    raise _error("mapping keys must be scalars", e)
                key = _key_text(_resolve(e))
                if key in mapping:
                    raise _error(f'duplicated mapping key "{key}"', e)
                mapping[key] = node(next(events))
        raise _error(f"unexpected YAML event {type(event).__name__}", event)

    first = next(events)  # StreamStart
    del first
    start = next(events)
    if isinstance(start, yaml.StreamEndEvent):
        return None
    value = node(next(events))
    next(events)  # DocumentEnd
    after = next(events)
    if not isinstance(after, yaml.StreamEndEvent):
        raise _Error(None, None, "expected a single document in the frontmatter", after.start_mark)
    return value
