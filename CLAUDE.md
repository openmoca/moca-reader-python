# moca-reader-python

The Python MOCA Reader, `moca-reader` / `moca_reader` ([ADR-0001](docs/adr/0001-reader-library-with-no-host-dependencies.md)).

- **No host dependencies.** Only the runtime dependencies in `pyproject.toml`; no web framework, no network clients.
- **The spec is the contract.** Normative sources in `../moca-spec/spec/`. The reference Reader (TypeScript) is `../moca-reader-typescript/lib/`; this Reader's modules map one-to-one onto it. When they disagree, the spec wins; raise the difference as an issue in moca-spec.
- **Match the reference exactly where Python differs from JavaScript**: `_js.py` holds those behaviours (UTF-16 sort order, `Math.round`, `Date.parse`, lenient base64, `JSON.stringify`, truthiness). Use it rather than Python's defaults.
- **Never raise for a malformed package.** Report diagnostics. Raise only for programmer errors.
- **Never reach the network or the host filesystem outside the package** because a package names something.
- Name things as the spec does, in Python's style; comment each rule with its section (`# Contract §3.2`).
- Checks: `uv run pytest`, `uv run ruff check`, `uv run ruff format --check`, `uv run mypy` (strict), the corpus through the runner, and `node tests/parity/parity.mjs`.
