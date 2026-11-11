# moca-reader

The MOCA Reader for Python: open a package from a directory, a `.moca` archive
or a host-supplied source; check it; compute its digest; verify attestations
and evidence; resolve members; answer structure operations; produce citation
records; and search with one entry point over lexical, dense-sidecar, store or
hybrid backends.

It implements the Reader class of the
[Reader contract](https://github.com/openmoca/moca-spec/blob/main/spec/moca-reader-contract.md),
follows the
[Reader interface](https://github.com/openmoca/moca-spec/blob/main/spec/moca-reader-interface.md)
with Python names, passes the whole
[conformance corpus](https://github.com/openmoca/moca-spec/blob/main/conformance/README.md),
and returns the same ranked results as the reference Reader,
[moca-reader-typescript](https://github.com/openmoca/moca-reader-typescript).

## Install

```sh
pip install moca-reader
```

Python 3.11 or later. [Getting started](docs/getting-started.md) takes you from
install to a cited search result and a conformance run in five steps.

```python
from moca_reader import Library, read_package

pkg = read_package("support-kb.moca", trust_root="trust-root.json")
print(pkg.valid, pkg.digest, pkg.capabilities)

library = Library().add(pkg)
for record in library.search("refund window", audiences=["public"]):
    print(record["node"]["title"], record["node"]["ref"], record["score"])
```

A malformed package never raises: `pkg.valid` is False and `pkg.diagnostics`
says why. The Reader never reaches the network, or any file outside the
package, because a package names it. Citation records are plain dicts, the
same JSON every MOCA Reader produces (`citation-record.schema.json`).

## The API

| Name | Purpose |
| --- | --- |
| `read_package(target, *, trust_root, resolve_member, strict, limits, known_profiles, now)` | Read and check a package: a path, a `.moca`/`.zip` path, or a host source with `list()` and `read(path)`. |
| `Library(clock=, overlays=, limits=)` | Holds verified packages, with bound sidecar chunks: `add`, `citations`, `get`, `search`, `structure`. |
| `Search(source, backend, audiences=, hooks=)` | One entry point over a backend: `search(query, limit=, include_all=, locale=, concepts=, scope=)`. The gate always runs last. `source` is a `Library`, or a `StoreScope(package_states, clock)` for a store backend: `package_state(result)` for each loaded package, so every library- and trust-dependent field is recomputed (contract §9.4). |
| `LexicalBackend`, `DenseBackend`, `MemoryStoreBackend`, `HybridBackend` | BM25 over package text or sidecar chunks; sidecar vectors with a host embedder (`S006`, `S007`); a reference in-memory store; Reciprocal Rank Fusion of a lexical and a dense backend. |
| `Embedder` | The protocol a host embedder follows: `name`, `version`, `dimensions`, `query_prefix`, `document_prefix`, `embed(texts, role)`. |
| `moca_reader.embedders` | MOCA's four standard embedding models run locally (`standard_embedder("bge-small-en-v1.5")`), with the `onnx` extra. |
| `SearchHooks`, `ontology_guided()`, `diversify(per_node=)` | Retrieval hooks: host code, never package content. |
| `bind_sidecar(target, pkg)` | Check a sidecar against a package and return usable chunks. |
| `directory_resolver(dirs)` | A simple member resolver over folders. |
| `TrustRoot` | A host trust root, from a path or a dict. |
| `flat_metadata(record)` | The consuming guide's flat `moca_*` fields for a citation record, for vector stores. |
| `library.structure` | `concept`, `requires`, `required_by`, `parts`, `narrower`, `broader`, `related`, `sequence`, `descendants`, `nodes`. |

The API is synchronous.

## Framework bindings

Separate packages, each a thin adapter over the Reader
([ADR-0002](docs/adr/0002-framework-bindings-as-thin-adapters.md)):

| Package | What it gives you |
| --- | --- |
| [`moca-reader-langchain`](packages/moca-reader-langchain/README.md) | `MocaRetriever`: a LangChain retriever returning `Document`s |
| [`moca-reader-llamaindex`](packages/moca-reader-llamaindex/README.md) | `MocaRetriever`: a LlamaIndex retriever returning scored nodes |

Both wrap a `Search` you build, so the gate and your audience filter always
apply, and carry the whole citation record and the consuming guide's flat
`moca_*` fields in each result's metadata. `flat_metadata(record)` gives you
the same fields for your own vector store.

## Search by meaning with a standard model

With the `onnx` extra, `moca_reader.embedders` runs MOCA's four standard
embedding models locally, the way every MOCA tool does, so a query embedded
here matches an index built with `moca-index --model`:

```sh
pip install "moca-reader[onnx]"
npx @openmoca/moca-embed models add bge-small-en-v1.5   # once: download and check the model
```

```python
from moca_reader import DenseBackend, HybridBackend, LexicalBackend
from moca_reader.embedders import standard_embedder

embedder = standard_embedder("bge-small-en-v1.5")  # files checked against their pinned SHA-256
hybrid = HybridBackend(LexicalBackend(library), DenseBackend(library, embedder))
```

Models are read from `~/.moca/models` (or `MOCA_MODELS`). The Reader never
downloads them.

## Lexical search

The built-in lexical backend is BM25 (k1 1.2, b 0.75) over node text, or over
sidecar chunks when a sidecar is bound. Every MOCA Reader tokenises the same
way, so they return the same results:

- NFKC-normalise, then lower-case each code point (simple case mapping).
- Letters, digits and combining marks make words; anything else separates
  them. Words in scripts with vowel signs, such as Devanagari, stay whole.
- Chinese, Japanese, Thai, Lao, Khmer and Myanmar text is split into each
  character (with its marks) and each pair of neighbouring characters.
- No stemming. A host that needs it supplies its own lexical backend.
- Without a locale, every language of a node is searched and its best match
  returned; with one, the representation package spec §5 selects.

Characters added in very recent Unicode versions can tokenise differently
across Readers, because each language runtime ships its own Unicode data.

## Conformance

As [Reader contract §14](https://github.com/openmoca/moca-spec/blob/main/spec/moca-reader-contract.md#14-demonstrating-conformance)
asks:

| | |
| --- | --- |
| Class | Reader |
| Contract version | 0.6.0 |
| Implemented | Archives, host sources, DSSE attestations, sidecars (lexical and dense), the ontology profile |
| Sigstore | Offline only, with the `sigstore` extra (`pip install moca-reader[sigstore]`), against the host trust root's `sigstore.trustedRoot`. Without the extra, or without a trusted root, a `*.sigstore.json` attestation is unverifiable (`A003`). There is no online mode: refresh the trusted root yourself (moca-spec attestations §6) |

The conformance adapter ships with the package. From a moca-spec checkout:

```sh
node scripts/run-conformance.mjs --reader "python -m moca_reader.conformance"
```

## Develop

You need [uv](https://docs.astral.sh/uv/). The tests read moca-spec's examples
and run its conformance corpus. Check out
[moca-spec](https://github.com/openmoca/moca-spec) beside this repository, or
set `MOCA_SPEC_DIR`. CI uses the tags pinned at the top of
`.github/workflows/test.yml` (`MOCA_SPEC_REF` and the like); check out the same
tags to match it.

```sh
uv sync
uv run pytest
uv run ruff check && uv run ruff format --check
uv run mypy
```

`tests/parity/parity.mjs` runs 18 search scenarios (87 queries) over
moca-spec's examples through this Reader and the reference Reader, and fails
on any difference in records, order, spans, text or scores. Dense sidecars use
a deterministic hashing embedder, so no model is needed. With
moca-reader-typescript and moca-tools (after `npm ci`) beside moca-spec:

```sh
node tests/parity/parity.mjs
```

## Release

1. Add a dated section to [CHANGELOG.md](CHANGELOG.md) and update `version` in
   `pyproject.toml` and `__version__` in `src/moca_reader/__init__.py`.
2. Point the `MOCA_*_REF` pins in `.github/workflows/test.yml` at the release tags
   ([moca-spec docs/releasing.md](https://github.com/openmoca/moca-spec/blob/main/docs/releasing.md#moving-the-pins)).
3. The tests, corpus and parity pass.
4. Tag `vX.Y.Z` and publish a GitHub release whose notes are the changelog
   section.
5. `uv build --all-packages` and `uv publish` from the tagged commit: `moca-reader`
   first, then its bindings, which release at the same version.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

OpenMOCA™ is a trade mark of PI & Mash Solutions Ltd. The licence covers the
code, not the name: see the
[trade mark policy](https://github.com/openmoca/moca-spec/blob/main/TRADEMARKS.md).
