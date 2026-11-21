"""The one-pass scanners give exactly what the regular expressions they replace gave, in time linear in the text
(Reader contract §3)."""

from __future__ import annotations

import random
import re
import time

import pytest

from moca_reader.content import link_targets
from moca_reader.evidence_text import JS_SPACE_CLASS, _link_text, html_text, markdown_text, strip_tags

WS = JS_SPACE_CLASS
LINK = re.compile(rf"!?\[[^\]]*\]\([{WS}]*(<[^>]+>|[^){WS}]+)(?:[{WS}]+(?:\"[^\"]*\"|'[^']*'))?[{WS}]*\)")
LINK_TEXT = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
SCRIPT_STYLE = re.compile(rf"<(script|style)\b[^>]*>[\s\S]*?</\1[{WS}]*>", re.I | re.A)
TAG = re.compile(r"<[^>]*>")


def samples(alphabet: list[str], count: int = 4000, longest: int = 24) -> list[str]:
    rng = random.Random(7)
    return ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, longest))) for _ in range(count)]


def test_link_targets_match_the_expression() -> None:
    for text in samples(["[", "]", "(", ")", "<", ">", "!", '"', "'", " ", "\t", "a", "b", "\u00a0"]):
        assert link_targets(text) == [m[1] for m in LINK.finditer(text)], text


def test_markdown_link_text_matches_the_expression() -> None:
    for text in samples(["[", "]", "(", ")", "!", "a", "b"]):
        assert _link_text(text) == LINK_TEXT.sub(r"\1", text), text


def test_html_text_matches_the_expressions() -> None:
    parts = ["<", ">", "/", "script", "STYLE", "Script", "style", " ", "a", "</script>", "<style>", "x", "\n"]
    for text in samples(parts, longest=16):
        assert html_text(text) == html_text_by_expression(text), text
        assert strip_tags(text) == TAG.sub("", text), text


def html_text_by_expression(text: str) -> str:
    # The entity step is shared; the samples hold no "&", so it changes nothing.
    return TAG.sub("", SCRIPT_STYLE.sub("", text))


@pytest.mark.parametrize(
    "text",
    [
        "[" * 80_000,
        "[a](" * 40_000,
        "[a](<" * 30_000,
        '[a](b "' * 30_000,
        "](" * 50_000,
    ],
)
def test_link_scans_are_linear(text: str) -> None:
    start = time.perf_counter()
    link_targets(text)
    markdown_text(text)
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize("text", ["<" * 160_000, "<script>" * 20_000, "<style " * 20_000 + "<script>x"])
def test_html_scans_are_linear(text: str) -> None:
    start = time.perf_counter()
    html_text(text)
    assert time.perf_counter() - start < 1.0
