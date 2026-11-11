# Architecture decision records

Each record states one decision, the options considered, and what would make
us revisit it. Records are numbered in order and never renumbered. A decision
that changes is superseded by a new record, not edited.

Decisions about the format and the Reader interface are in
[moca-spec](https://github.com/openmoca/moca-spec/blob/main/docs/adr/README.md).
These are the decisions about this Reader.

| ADR | Decision |
| --- | --- |
| [0001](0001-reader-library-with-no-host-dependencies.md) | A Python Reader library with no host dependencies, matching the reference Reader exactly |
| [0002](0002-framework-bindings-as-thin-adapters.md) | LangChain and LlamaIndex bindings as thin adapters, one package each |

New records use the template in [0000-template.md](0000-template.md).
