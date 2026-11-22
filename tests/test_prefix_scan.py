"""The one-pass prefix scanner gives exactly what the expression it replaces gave, in steps linear in the text
(Reader contract §3)."""

from __future__ import annotations

import random
import re

import pytest

from moca_reader.structure import declared_prefixes

WS = "\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
# The expression the scanner replaces, kept here as the reference for its answers.
PREFIX_DECL = re.compile(
    rf"^[{WS}]*(?:@prefix|PREFIX)[{WS}]+([A-Za-z][A-Za-z0-9_.-]*)?:",
    re.IGNORECASE | re.ASCII | re.MULTILINE,
)
MIB = 1024 * 1024


def by_expression(text: str) -> list[str]:
    return [m[1] for m in PREFIX_DECL.finditer(text) if m[1]]


FORMS = [
    # @prefix and PREFIX forms
    "@prefix ex: <http://example.org/> .",
    "PREFIX ex: <http://example.org/>",
    "@prefix ex:<http://example.org/> .",
    "@prefix ex: <a> .\n@prefix skos: <b> .\nPREFIX dct: <c>\n",
    # case
    "@PREFIX ex: <a> .",
    "@Prefix ex: <a> .",
    "prefix ex: <a>",
    "Prefix Ex: <a>",
    "pReFiX eX: <a>",
    "@pr\u0130fix ex: <a> .",  # not ASCII: not the keyword
    "\u212aprefix ex: <a>",
    # comments
    "# @prefix ex: <a> .",
    "#@prefix ex: <a> .\n@prefix real: <b> .",
    "@prefix ex: <a> . # @prefix other: <b> .",
    "@prefix ex: <a> . @prefix same: <b> .",
    # white space
    "   @prefix ex: <a> .",
    "\t\t@prefix ex: <a> .",
    "\n\n\n@prefix ex: <a> .",
    "\r\n@prefix ex: <a> .\r\n@prefix two: <b> .",
    "\u00a0\u2028\u3000\ufeff@prefix ex: <a> .",
    "@prefix\nex: <a> .",
    "@prefix\n\n  \t ex: <a> .",
    "@prefix\n@prefix ex: <a> .",
    "@prefix \n PREFIX ex: <a>",
    "@prefix\u2028ex: <a> .",
    "\u2028@prefix ex: <a> .",
    "x\u2028@prefix ex: <a> .",
    "x\r@prefix ex: <a> .",
    "@prefixex: <a> .",
    "PREFIXex: <a>",
    "@prefix: <a> .",
    "@prefix   ",
    "@prefix",
    "",
    "\n",
    # IRIs and names
    "@prefix ex: <http://example.org/a#b> .",
    "@prefix a.b-c_d9: <a> .",
    "@prefix 9a: <a> .",
    "@prefix _a: <a> .",
    "@prefix -a: <a> .",
    "@prefix a b: <a> .",
    "@prefix ab\n: <a> .",
    "@prefix ex <a> .",
    "@prefix ex\n@prefix two: <a> .",
    "@prefix prefix: <a> .",
    "@prefix prefix\nPREFIX x: <a>",
    "@prefix \u00e9t\u00e9: <a> .",
    "@prefix ex\u00e9: <a> .",
    "<s> <p> <o> .\n@prefix late: <a> .",
    '<s> <p> """\n@prefix inString: <a> .\n""" .',
    # the empty prefix
    "@prefix : <http://example.org/> .",
    "PREFIX : <a>",
    "@prefix : <a> .\n@prefix ex: <b> .",
    "@prefix\n: <a> .",
]


@pytest.mark.parametrize("text", FORMS)
def test_each_form_gives_what_the_expression_gave(text: str) -> None:
    assert declared_prefixes(text)[0] == by_expression(text)


def test_random_texts_give_what_the_expression_gave() -> None:
    parts = [
        "@prefix",
        "PREFIX",
        "prefix",
        "@PrEfIx",
        "@pre",
        " ",
        "\t",
        "\n",
        "\r",
        "\u2028",
        "\u00a0",
        ":",
        "ex",
        "a.b",
        "9",
        "-",
        "#",
        "<a>",
        " .",
        "\u00e9",
    ]
    rng = random.Random(7)
    for _ in range(20_000):
        text = "".join(rng.choice(parts) for _ in range(rng.randint(0, 14)))
        assert declared_prefixes(text)[0] == by_expression(text), repr(text)


LARGE = [
    pytest.param("\n" * (4 * MIB), id="blank lines"),
    pytest.param(" " * (4 * MIB), id="spaces"),
    pytest.param("@prefix " * (MIB // 2), id="keyword on one line"),
    pytest.param("@prefix\n" * (MIB // 2), id="keyword on each line"),
    pytest.param("PREFIX\n" * (MIB // 2), id="bare keyword on each line"),
    pytest.param("@prefix prefix\n" * (MIB // 4), id="keyword and name on each line"),
]


@pytest.mark.parametrize("text", LARGE)
def test_steps_are_linear_in_the_text(text: str) -> None:
    # Steps, not time: a step is one character read. Twice the length is the bound, and half the text takes
    # half the steps (give or take one line), so the count grows in step with the text.
    _, steps = declared_prefixes(text)
    assert steps <= 2 * len(text)
    _, half = declared_prefixes(text[: len(text) // 2])
    assert abs(2 * half - steps) <= 64
