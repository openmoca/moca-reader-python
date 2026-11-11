# 0002 — LangChain and LlamaIndex bindings as thin adapters, one package each

- **Status:** Accepted
- **Date:** 2026-10-30
- **Deciders:** MOCA maintainer

## Context

The [Reader interface §7](https://github.com/openmoca/moca-spec/blob/main/spec/moca-reader-interface.md#7-bindings)
lists LangChain ("a retriever returning documents") and LlamaIndex ("a
retriever returning nodes with scores") for Python. A binding must carry the
whole citation record in the framework type's metadata, including `node.ref`,
and, where the framework needs flat metadata, at least the consuming guide's
`moca_*` fields. The .NET Reader set the pattern for bindings: thin adapters,
one package per framework, in the Reader's repository (moca-reader-dotnet
ADR-0004).

## Options

1. One package per framework, in this repository, as a uv workspace.
2. Optional extras of `moca-reader` (`moca-reader[langchain]`).
3. Packages in their own repositories.

## Decision

Option 1. `moca-reader-langchain` and `moca-reader-llamaindex`, in
`packages/`, each depending on `moca-reader` and one framework's core package,
never the reverse. Extras would put framework code inside `moca_reader`; their
own repositories would split one Reader's release across several.

- Each `MocaRetriever` wraps a host-built `moca_reader.Search`, so the gate,
  the retrieval policy and the host's audience filter always apply; the search
  options are set when the retriever is built, never by a caller.
- Each result carries the whole record under `moca_citation` and the flat
  fields from `moca_reader.flat_metadata`, which hosts writing to their own
  stores use too. A test checks the field names against the consuming guide.
- LlamaIndex nodes exclude the MOCA keys from what a model or an embedder sees.
- No asynchronous search yet: LangChain's async path runs the same search.
- The retrievers never build prompts; their READMEs say how to hand text to a
  model (Reader contract §12).

## Consequences

- A host installs only the framework it uses.
- The three packages release together, at the same version.
- A framework's breaking change touches one small package.

## What would change this decision

A framework whose retrievers need an asynchronous search to perform well: then
the Reader gains `asearch`, and the binding uses it.
