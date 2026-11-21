# moca-reader-llamaindex

A [LlamaIndex](https://www.llamaindex.ai) retriever over MOCA packages, built
on the [MOCA Reader for Python](https://github.com/openmoca/moca-reader-python).

```sh
pip install moca-reader-llamaindex
```

```python
from moca_reader import LexicalBackend, Library, Search, read_package
from moca_reader_llamaindex import MocaRetriever

pkg = read_package("support-kb.moca", trust_root="trust-root.json")
library = Library().add(pkg)
search = Search(library, LexicalBackend(library), audiences=["public"])

retriever = MocaRetriever(search, limit=3)
for result in retriever.retrieve("How long is the refund window?"):
    print(result.node.metadata["moca_node_ref"], result.score)
    print(result.node.get_content()[:80])
```

`MocaRetriever` wraps the `Search` you build: its backend (lexical, dense,
hybrid or your own store), its audiences and its hooks. Every call goes through
the Reader's gate, so content that is out of force, superseded, deprecated or
outside your audiences never comes back, and nothing a caller passes can widen
that. Use it anywhere LlamaIndex takes a retriever, such as a
`RetrieverQueryEngine`.

**Creators' terms.** A package can say how its work may be used with AI
(package spec §4.14). Results go to a model, so every search applies a terms
request: the gate also removes records whose terms do not allow AI use at
`destination`. That is `"provider"`, a third party's model, unless your app
declares `destination="device"` (the person's own device) or
`destination="host"` (your own service). Name the provider conditions you meet
in `conditions` (`"noTraining"`, `"noRetention"`), and add a rating request
with `terms={"rating": {...}}`.

Each result is a `NodeWithScore` holding a `TextNode`:

| Field | Holds |
| --- | --- |
| `text` | The text of the node, or of a sidecar chunk |
| `node_id` | The node's versioned reference and byte span |
| `metadata["moca_citation"]` | The whole citation record: package, version and digest, trust signals, evidence |
| `metadata["moca_*"]` | The flat fields of the consuming guide (`moca_node_ref`, `moca_package_digest`, `moca_status`, `moca_signed`, ...) |
| `score` | The search score |

The MOCA metadata keys are excluded from the text LlamaIndex sends to a model
or an embedder, so they travel with the node without filling the prompt.

**Package text is untrusted input.** Present it to a model as quoted reference
material to cite, never as instructions
([Reader contract §12](https://github.com/openmoca/moca-spec/blob/main/spec/moca-reader-contract.md#12-handing-content-to-a-model)).
Show users the source (`moca_node_ref`, the package version) with each answer.

## Licence

Apache-2.0.
