"""Package spec §5.1: frontmatter numbers too large to be finite, and implicit keys of at most 1,024 characters."""

from __future__ import annotations

import math

from moca_reader.frontmatter import split_frontmatter


def _read(yaml: str) -> object:
    return split_frontmatter(f"---\ntype: Note\n{yaml}\n---\n")


def test_an_implicit_key_of_1024_characters_is_read_and_one_of_1025_is_refused() -> None:
    assert getattr(_read("k" * 1024 + ": v"), "error", None) is None
    assert getattr(_read("k" * 1025 + ": v"), "error", None)
    assert getattr(_read('"' + "k" * 1023 + '": v'), "error", None)  # the quotes count
    assert getattr(_read("? " + "k" * 3000 + "\n: v"), "error", None) is None  # an explicit key may be longer


def test_integers_too_large_for_a_double_are_read_as_inf_is() -> None:
    data = getattr(_read(f"a: {'9' * 5000}\nb: 0x{'f' * 300}\nc: 0o{'7' * 400}\nd: 0x10000000000000801"), "data", None)
    assert isinstance(data, dict)
    assert math.isinf(data["a"])
    assert math.isinf(data["b"])
    assert math.isinf(data["c"])
    assert float(data["d"]) == 2.0**64 + 4096
