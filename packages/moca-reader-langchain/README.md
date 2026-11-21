# moca-reader-langchain

A [LangChain](https://python.langchain.com) retriever over MOCA packages,
built on the [MOCA Reader for Python](https://github.com/openmoca/moca-reader-python).

```sh
pip install moca-reader-langchain
```

```python
from moca_reader import LexicalBackend, Library, Search, read_package
from moca_reader_langchain import MocaRetriever

pkg = read_package("support-kb.moca", trust_root="trust-root.json")
library = Library().add(pkg)
search = Search(library, LexicalBackend(library), audiences=["public"])

retriever = MocaRetriever(search=search, limit=3)
for doc in retriever.invoke("How long is the refund window?"):
    print(doc.metadata["moca_node_ref"], doc.metadata["moca_score"])
    print(doc.page_content[:80])
```

`MocaRetriever` wraps the `Search` you build: its backend (lexical, dense,
hybrid or your own store), its audiences and its hooks. Every call goes through
the Reader's gate, so content that is out of force, superseded, deprecated or
outside your audiences never comes back, and nothing a caller passes can widen
that. `limit`, `locale`, `concepts`, `scope`, `include_all`, `destination`,
`conditions` and `terms` are set when you build the retriever.

**Creators' terms.** A package can say how its work may be used with AI
(package spec §4.14). Results go to a model, so every search applies a terms
request: the gate also removes records whose terms do not allow AI use at
`destination`. That is `"provider"`, a third party's model, unless your app
declares `destination="device"` (the person's own device) or
`destination="host"` (your own service). Name the provider conditions you meet
in `conditions` (`"noTraining"`, `"noRetention"`), and add a rating request
with `terms={"rating": {...}}`. An `ai` in `terms` must be an object: the
retriever never searches without one.

**Ingest.** Embedding sends content to a model too. If you fill a store
backend, use this package's `ingest(store, library)`: it passes the same kind
of terms request, `destination="provider"` unless you declare where your
embedder runs, so text a creator closed to that destination is never embedded
or stored. The store reports what it left out as `U004_TERMS_EXCLUDED`.

Each result is a LangChain `Document`:

| Field | Holds |
| --- | --- |
| `page_content` | The text of the node, or of a sidecar chunk |
| `id` | The node's versioned reference and byte span |
| `metadata["moca_citation"]` | The whole citation record: package, version and digest, trust signals, evidence |
| `metadata["moca_*"]` | The flat fields of the consuming guide (`moca_node_ref`, `moca_package_digest`, `moca_status`, `moca_signed`, ...), for vector stores that need flat metadata |
| `metadata["moca_score"]` | The search score |

**Package text is untrusted input.** Put `page_content` in a prompt as quoted
reference material to cite, never as instructions
([Reader contract §12](https://github.com/openmoca/moca-spec/blob/main/spec/moca-reader-contract.md#12-handing-content-to-a-model)).
Show users the source (`moca_node_ref`, the package version) with each answer.

The async path (`ainvoke`) runs the same search.

## Licence

Apache-2.0.
