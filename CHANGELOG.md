# Changelog

All notable changes to `moca-reader`. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.6.0] - 2026-11-11

### Added (Sigstore, offline)

- With the `sigstore` extra, Sigstore bundles are verified offline against the
  host's `sigstore.trustedRoot`, through sigstore-python 4.x. Without the extra
  or a trusted root they stay A003; identities listed but none for the role is
  A002, as in the reference Reader. There is no online mode. The corpus's
  `sigstore-*` cases pass.

### Fixed (attestations §5)

- Strict Ed25519 checks before verifying: A and R are canonical points of
  prime order, S < L. Before, a trusted small-order key verified a signature
  of any message.

### Fixed (frontmatter line ends)

- Only LF or CRLF ends a line in the frontmatter block, in every Reader. The
  reference Reader also ended lines at a lone CR, U+2028 and U+2029.

### Fixed (edge cases)

- Regular expressions and trimming follow package spec §2: ASCII digits,
  ECMAScript white space, and an absolute end of string. Before, a date in
  non-ASCII digits parsed, and a trailing newline passed several checks.
- An archive entry with a bad CRC-32 raised `BadZipFile`; it is now P002, as
  is a stored entry whose size does not match its header.
- M007 knows every IANA formal URN namespace and informal ones.
- A leading byte order mark is not part of an evidence source.

### Changed (conformance adapter)

- The adapter passes the corpus option `strict`.

### Added (versioning, package spec §14)

- `M009_MOCA_VERSION_NEWER` (warning) for a package written for a newer
  `mocaVersion` than `MOCA_VERSION` (`0.6`). Versions compare numerically, without
  overflow. The `mocaVersion` check uses a full match, so a trailing newline no longer counts. The vendored schemas have portable patterns.

### Added (composition limits, package spec §7.1.1)

- Member resolution is bounded: `limits={"maxMemberDepth": …, "maxMembers": …}` (defaults 8 and 256, across every
  depth of one read). A member past either limit is not resolved, and
  `R001_MEMBER_UNRESOLVED` says why.

### Removed (structure.json, moca-spec ADR-0019)

- The Reader no longer reads or checks `structure.json`, and
  `O004_STRUCTURE_VIEW_MISMATCH` is retired. A package that ships the file
  stays valid and gets `structured` from `structure.ttl` alone. `structure_view` stays.

### Changed (sidecars and search)

- A sidecar item's `text` must equal the package's bytes at its span, which
  must lie in the body (`S004`); lexical search reads the package's bytes, never
  the sidecar's text, so a sidecar cannot stuff keywords into a node.
- A prefix declared by only the index or only the embedder is `S006`.
- The gate keeps one result per node representation and span: the English and
  French pages of one node are no longer merged.

### Changed (determinism)

- `moca.json` and attestation statements that repeat a member name are `M001`
  and `A001` (they were read with the last value).
- Locale fallback: exact, then the longest tag the request starts with, then the
  lowest tag starting with the request, all case-insensitive.
- Evidence: Markdown and HTML quotes are normalised like their sources, and a
  `TextPositionSelector` on its own is no longer checked (`matched` absent).

### Changed (limits and archives, review B9 and M6)

- Evidence work is bounded per package (`maxEvidenceChecksPerPackage`, 10,000;
  `maxEvidenceBytesPerPackage`, 256 MiB scanned), each source is normalised once,
  and a quote is matched in one pass. A package of 200 nodes with 256 quotes each
  against an 8 MiB source now reads in well under a second.
- Directories have the entry and byte limits, and a file replaced by a link
  after listing is unreadable.
- Archives: names must be UTF-8 (flag set) with no NUL, empty or `.` segments;
  duplicate entries are `P003`; only stored and deflated entries are read
  (others `P002`), and an unreadable entry stops the read.

### Changed (identity and tampering, review M2 and M3)

- A library refuses a second package with the same `id@version` and a different
  digest, and reports `L001_IDENTITY_CONFLICT` (it was dropped silently).
- A package attestation naming this `id@version` with another digest is
  `A008_PACKAGE_DIGEST_MISMATCH`, not `A002`.
- A resolved member whose `id` or `version` differs from its pin is `R002`.
- `read_package(target, require_signature=True)` makes a package without a valid package attestation invalid
  (`A009_SIGNATURE_REQUIRED`).

### Changed (store search, review B2)

- A store search takes the loaded packages' states (`package_state(result)`; `StoreScope(states, clock)`) instead of bare
  digests, and recomputes `superseded`, `contested`, `signed`, `signers`,
  `attestedReviews` and `reviewStatus` at query time (contract §9.4). A package
  superseded after ingest, or a key removed from the trust root, is reflected
  at once.

### Changed (reviews, moca-spec ADR-0017)

- `reviewed` needs a signed package with every reviewed file approved.
  Citation records gain `trust.reviewStatus` (`approved`, `disputed`,
  `unverified`, `none`) and each review's `packageVerified`. The latest review
  from each signer counts; a review dated after the clock is ignored
  (`A007_REVIEW_DATE_FUTURE`); a trust-root entry's `reviewers` list limits whom
  its key may sign as.

### Changed (audience, moca-spec ADR-0016)

- Under a host audience set, content with no audience label is left out unless
  the host allows it (`Search(..., allow_unlabelled=True)`, off by default), and a malformed label never
  matches; citation records mark it `audienceInvalid`. A translation with no
  label has its default representation's. The gate, the backends and the store
  backend apply the same rule.

### Changed (relations, moca-spec ADR-0015)

- `supersedes` and `conflictsWith` take effect only when the declaring package
  has a valid package attestation from a key or Sigstore identity whose new
  trust-root `ids` cover the target's id (package spec §7.2). Otherwise the
  Reader reports `R004_RELATION_UNAUTHORISED` (info) and the relation has no
  effect. `Library(allow_unsigned_relations=True)` (off by default) applies unsigned relations, for a library
  of the host's own packages.

### Changed

Dates follow package spec §4.4:

- A full date means 00:00Z; a date-time needs an offset, and one without is
  ignored (it already has a diagnostic) rather than read as UTC.
- A node's validity window is the intersection with its package's: a node can
  no longer stay in force after the package's `validUntil`. An inverted window
  is ignored.
- A trust-root key is not trusted from the instant of `expires`, checked
  against the host clock, which `read_package` now takes (`clock`, a callable returning a `datetime`). A key whose `expires`
  does not parse is not trusted.

Attestation verification follows the numbered algorithm now in attestations §7
(0.6.0):

- DSSE payloads and signatures are decoded strictly: base64 or base64url, with
  or without padding. Anything else makes the payload malformed (`A001`) or the
  signature not verify.
- A trust root is refused if it repeats a `keyid` or has a key or identity
  without `roles`. An empty `roles` list trusts the entry for nothing.

### Fixed

Fixes from the 10 November 2026 specification review, each with a new case
in the moca-spec 0.6.0 conformance corpus:

- A malformed percent-encoding in a source `resource` or a link is reported as
  `C008_UNSAFE_PATH` instead of being silently skipped.
- An absolute reference (a leading `/` or `\`, or a drive prefix such as `C:/`)
  is `C008_UNSAFE_PATH`, as the Reader contract says. It was resolved under
  `content/`.
- Structure traversal is iterative: a 30,000-concept `requires` chain no longer
  risks the recursion limit.
- A validity bound or `stale_after` that does not parse as a date is treated as
  absent; it no longer takes a node out of force.
- A `generated` or `verified` entry with no `by` is dropped; it was reported
  with the actor `"undefined"`.
- `log.md` and `index.md` frontmatter gets the frontmatter size limit, and a
  level-two heading (`##`) inside a fenced code block in `log.md` is no longer a C004 error.
- `moca.json` that is not valid UTF-8 is `M001`; it was read with replacement
  characters.
- Only entries under `attestations/` are left out of the digest; a top-level
  file named `attestations` is digested.
- Member cycles are detected by `id@version`, so a package can compose another
  version of itself.
- A host source's byte limit is also enforced on the bytes it returns, and a
  limit broken while reading is one `T003`, not a `P002` per file. An existing
  file that is not a directory or a `.moca`/`.zip` archive is `T002`.
- Archive bytes are accepted as a target.
- A trust-root key or identity with an empty `roles` list is trusted for
  nothing. It was trusted for both roles: a key a host disabled by emptying its
  roles stayed live.

## [0.5.0] - Not published

The first release. It implements moca-spec 0.5 (0.5.0), passes all 93
cases of the 0.5.0 conformance corpus, both as pytest cases and
through the runner protocol, and returns the same ranked results as the
reference Reader in all 87 parity queries.


### Performance

- **Lexical search keeps each document's term counts** after its first search,
  per package digest, and drops them when the package leaves the library.
  Later searches only score: at 5,000 pages, about 21 ms a search after the
  first. Scores and order are unchanged (the corpus and the parity check
  against the reference Reader pass).

### Added

- `moca_reader.embedders`, with the `onnx` extra: MOCA's four standard embedding
  models (`bge-small-en-v1.5`, `nomic-embed-text-v1.5`, `all-MiniLM-L6-v2`,
  `multilingual-e5-small`) run locally, pinned by commit and SHA-256, checked
  before loading. Vectors match `moca-index --model`, the .NET Reader's ONNX
  binding and the MCP server exactly.
### Added

- `read_package`: directories, `.moca` archives and host sources; the
  moca-digest-v2 digest; DSSE package and review attestations against a host
  trust root, with Ed25519 keys only (attestations §5); members through a host resolver; content, evidence checks,
  structure and capabilities. Sigstore bundles are reported as unverifiable
  (`A003`).
- `Library`, `Search` and the gate; `LexicalBackend` (BM25 with the shared
  tokeniser), `DenseBackend` over sidecar vectors (`S006`, `S007`,
  `model.distance`, compared embedder prefixes), `MemoryStoreBackend`,
  `HybridBackend` (Reciprocal Rank Fusion); `ontology_guided` and `diversify`
  hooks; structure operations.
- `bind_sidecar` for `moca-jsonl-v1` sidecars, with float32 vectors.
- `python -m moca_reader.conformance`: the runner protocol adapter, shipped
  with the package.
- `flat_metadata(record)` and `FLAT_FIELDS`: the consuming guide's flat
  `moca_*` fields for a citation record.
- `moca-reader-langchain` and `moca-reader-llamaindex`: `MocaRetriever` for
  each framework, over a host-built `Search`, carrying the whole citation
  record and the flat fields in each result's metadata (ADR-0002).
