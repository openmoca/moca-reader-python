# Fuzzing

Packages are untrusted archives, so the Reader's open-and-search path is fuzzed with
[Atheris](https://github.com/google/atheris), a coverage-guided fuzzer, seeded from moca-spec's conformance corpus.

| Target | Input | What fails it |
| --- | --- | --- |
| `open_search.py` | Archive bytes, read with `read_package` | Any exception from `read_package`, or from searching a package that read as valid |
| `package_files.py` | One file of a valid package replaced (manifest, frontmatter, Turtle), read through a host source | The same |

`read_package` never raises for a malformed package: a damaged archive is a diagnostic (T003 or P002). A crash, a
timeout or running out of memory is a bug: fix it, and add a test in `tests/` (as `tests/test_archive_robustness.py`
does) or a case to moca-spec's corpus.

## Run locally

Atheris has wheels for CPython 3.12 to 3.14 on Linux x86_64 only, so on another system run it in a container. With
moca-spec checked out beside this repository:

```sh
uv sync --locked --no-dev --python 3.13
uv pip install --require-hashes -r fuzz/requirements.txt
uv run --no-sync python fuzz/seed.py ../moca-spec fuzz/corpus     # builds fuzz/corpus and fuzz/corpus-files
cd fuzz
uv run --no-sync python open_search.py kept-open corpus -max_total_time=60
uv run --no-sync python package_files.py kept-files corpus-files -max_total_time=60
```

Set `MOCA_SPEC_DIR` if moca-spec is elsewhere, and `MOCA_FUZZ_BASE` to fuzz a different fixture's files (by default
`structure-procedure`).

## In CI

`.github/workflows/fuzz.yml` runs each target for 60 seconds on pull requests that touch `src/`, `fuzz/` or
`uv.lock`, and for 30 minutes nightly, keeping the corpus between nightly runs. Crashing inputs are uploaded as an
artifact. Seeds come from moca-spec at the same ref as `test.yml`.
