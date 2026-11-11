# Getting started with the Python Reader

Install the Python MOCA Reader, open an example package, search it and cite
what you find, then run the conformance corpus. You need Python 3.11 or later,
and Node.js 22 or later for the corpus runner.

## 1. Install the Reader

```sh
mkdir moca-start && cd moca-start
python3 -m venv .venv
. .venv/bin/activate
pip install moca-reader
```

## 2. Get an example package

`support-kb` is a small customer-support knowledge base: a refund policy in
English and French, a shipping guide, and an internal account-deletion
procedure. It is signed, one node has a signed review, and the refund policy
quotes the customer terms it came from, which travel inside the package.

```sh
curl -fsSLO https://github.com/openmoca/moca-spec/releases/download/v0.6.0/support-kb.moca
curl -fsSLO https://github.com/openmoca/moca-spec/releases/download/v0.6.0/example-trust-root.json
```

The trust root says whose signatures you accept, and for what. This one trusts
the example keys, which are published on purpose: use it for the examples
only. To make your own, see
[your trust root](https://github.com/openmoca/moca-spec/blob/main/docs/guides/consuming.md#your-trust-root).

## 3. Open it

```python title="open.py"
import sys

from moca_reader import read_package

pkg = read_package("support-kb.moca", trust_root="example-trust-root.json")
if not pkg.valid:
    for d in pkg.diagnostics:
        print(d.code, d.message, file=sys.stderr)
    sys.exit(1)

print(pkg.digest)
print(", ".join(pkg.capabilities))
```

```sh
python open.py
```

```text
sha256:4992176b90ea0992037617ee56d5dcafecf60aeb400cfa9369c9164453df96da
core, localized, located-evidence, reviewed, self-contained-evidence, signed
```

The digest covers every file in the package: change one byte and it changes.
`signed` and `reviewed` appear because the signatures verify against your trust
root; without one, they are reported as unverifiable. `read_package` never
raises for a bad package: problems come back as diagnostics with stable codes.

## 4. Search and cite

```python title="search.py"
from moca_reader import LexicalBackend, Library, Search, read_package

pkg = read_package("support-kb.moca", trust_root="example-trust-root.json")
library = Library().add(pkg)
search = Search(library, LexicalBackend(library), audiences=["public"])

hits = search.search("How long is the refund window?", limit=1)
if not hits:
    raise SystemExit("no result")
hit = hits[0]

print(hit["text"].strip())
print()
print(f"Source:   {hit['node']['title']} ({hit['node']['ref']})")
print(f"Package:  {hit['package']['id']} {hit['package']['version']}, signed: {hit['package']['signed']}")
print(f"Digest:   {hit['package']['digest']}")
reviewers = ", ".join(r["reviewer"] for r in hit["trust"]["attestedReviews"])
print(f"Reviewed: {reviewers or 'no'}")
matched = all(e.get("matched") for e in hit["evidence"])
print(f"Evidence: {'every quote found in its source' if matched else 'not all checked'}")
```

```sh
python search.py
```

Each result is a **citation record**: the text, plus the package, version and
digest it came from, a versioned reference to the node, its trust signals, and
its evidence, marked `matched` when the quote was found in the original. It is
a plain dict, the same JSON every MOCA Reader produces. Show your users where
an answer came from, and log the digest with the answer so you can prove later
what was read.

The search left out the internal account-deletion procedure: you asked for the
`public` audience only, and nothing a caller does can widen that. It also
leaves out content that is superseded, out of force or deprecated, unless you
pass `include_all=True`.

When you hand results to a model, pass the text as quoted reference material,
never as instructions
([Reader contract §12](https://github.com/openmoca/moca-spec/blob/main/spec/moca-reader-contract.md#12-handing-content-to-a-model)).

## 5. Run the conformance corpus

The corpus is how every MOCA Reader, in any language, shows it reads packages
the same way. The Reader you installed carries its conformance adapter, so
moca-spec's runner can drive it directly:

```sh
cd ..
git clone --depth 1 --branch v0.6.0 https://github.com/openmoca/moca-spec.git
cd moca-spec
npm ci
node scripts/run-conformance.mjs --reader "python -m moca_reader.conformance" --without sigstore
```

```text
All 189 conformance case(s) pass; 7 skipped (without sigstore).
```

The seven skipped cases check Sigstore signatures, which this Reader verifies
only with the `sigstore` extra. With `pip install "moca-reader[sigstore]"`,
leave out `--without sigstore` and all 196 pass.

## Next

- [Consuming packages](https://github.com/openmoca/moca-spec/blob/main/docs/guides/consuming.md):
  your own retrieval stack, structure, dense search and MCP.
- [The Python Reader](../README.md): the API, dense and hybrid search, and the
  conformance statement.
