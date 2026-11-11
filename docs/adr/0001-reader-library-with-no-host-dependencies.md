# 0001 — A Python Reader library with no host dependencies, matching the reference Reader exactly

- **Status:** Accepted
- **Date:** 2026-10-30
- **Deciders:** MOCA maintainer

## Context

Most developers building AI and RAG systems work in Python. MOCA has a
reference Reader in TypeScript and a Reader in .NET; both pass the conformance
corpus and return the same ranked results. A Python Reader must do the same,
and be easy to use from scripts, notebooks and agent frameworks.

## Options

1. A port of the reference Reader, module for module, with Python names.
2. A wrapper that runs the TypeScript Reader in a JavaScript engine.
3. A new design around Python idioms.

## Decision

Option 1. `moca-reader` on PyPI, `import moca_reader`, Python 3.11 and later.

- **A library with no host dependencies.** PyYAML, jsonschema,
  rfc3339-validator, rdflib and cryptography only. Host features live in the
  host.
- **The spec's names, in Python's style.** `read_package`, `Library`,
  `Search(...).search(...)`, `bind_sidecar`; host-supplied objects
  (`Embedder`, backends, sources) are `typing.Protocol`s.
- **Synchronous first.** Plain calls work in scripts and notebooks. An
  asynchronous search comes with the framework bindings.
- **Citation records are dicts**, the same JSON every Reader produces, so a
  record from this Reader and from the reference Reader compare equal.
- **Exactly the reference's behaviour where Python's defaults differ.**
  `_js.py` holds them: UTF-16 string order, `Math.round`, `Date.parse`,
  lenient base64, `JSON.stringify` and truthiness. Frontmatter uses the YAML 1.2
  core schema on PyYAML's event stream, not PyYAML's YAML 1.1 resolvers.
  Lower-casing uses the simple mapping per code point, not `str.lower`.
  rdflib's triples are taken in document order.
- **The whole corpus, three ways.** pytest runs `cases.json`; the runner
  protocol drives `python -m moca_reader.conformance`, which ships with the
  package; and `tests/parity/parity.mjs` compares ranking with the reference
  Reader.

## Consequences

- A host can read, verify and search packages in-process without a JavaScript
  runtime.
- Sigstore bundles are not verified yet; they are reported as unverifiable
  (`A003`), as the .NET Reader does.
- Framework bindings (LangChain and LlamaIndex retrievers) are separate
  packages that depend on `moca-reader`, never the reverse.

## What would change this decision

A host that needs a Reader feature the interface does not define. That
becomes a Spec Change Proposal in moca-spec, not a host dependency here.
