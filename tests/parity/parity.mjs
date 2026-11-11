#!/usr/bin/env node
// Parity with the reference Reader. The conformance corpus never compares
// ranking; this does. It runs the same search scenarios over moca-spec's
// examples through the reference Reader (moca-reader-typescript) and this
// Reader (Python), and fails on any difference in the records returned, their order,
// spans, text or scores.
//
// Dense sidecars are built with moca-index and a deterministic hashing
// embedder: each Reader's own tokeniser, FNV-1a into 64 buckets, counts as
// the vector. Counts are exact in float32 and double, so both Readers compute
// the same scores. No model is needed.
//
// Usage, with moca-spec, moca-reader-typescript and moca-tools (npm ci'd)
// checked out beside this repository:
//   node tests/parity/parity.mjs
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..');
const siblings = dirname(repo);
const spec = process.env.MOCA_SPEC_DIR ?? join(siblings, 'moca-spec');
const reader = await import(join(siblings, 'moca-reader-typescript', 'lib', 'index.js'));
const { tokens } = await import(join(siblings, 'moca-reader-typescript', 'lib', 'backends', 'bm25.js'));
const { buildSidecar } = await import(join(siblings, 'moca-tools', 'packages', 'moca-index', 'lib', 'index.js'));

const DIMENSIONS = 64;
function fnv1a(text) {
  let h = 0x811c9dc5;
  for (const byte of Buffer.from(text, 'utf8')) h = Math.imul(h ^ byte, 0x01000193) >>> 0;
  return h;
}
const hashing = (name = 'parity-hash') => ({
  name,
  version: '1',
  dimensions: DIMENSIONS,
  embed: async (texts) => texts.map((t) => {
    const v = new Array(DIMENSIONS).fill(0);
    for (const token of tokens(t)) v[fnv1a(token) % DIMENSIONS] += 1;
    return v;
  }),
});

const config = JSON.parse(readFileSync(join(here, 'scenarios.json'), 'utf8'));
const work = mkdtempSync(join(tmpdir(), 'moca-parity-'));
try {
  // Sidecars, built once by moca-index.
  for (const [name, s] of Object.entries(config.sidecars)) {
    const out = join(work, name);
    if (s.from) {
      cpSync(join(work, s.from), out, { recursive: true });
      const items = join(out, 'payload', 'items.jsonl');
      writeFileSync(items, `${readFileSync(items, 'utf8').trim().split('\n').map((l) => { const { text, ...i } = JSON.parse(l); return JSON.stringify(i); }).join('\n')}\n`);
      continue;
    }
    await buildSidecar({ pkg: join(spec, config.packages[s.package]), out, chunker: s.chunk, zip: !!s.zip, force: true, ...(s.embedder ? { embedder: hashing() } : {}) });
  }

  const reference = await runReference();
  const py = spawnSync('uv', ['run', '--quiet', 'python', join(here, 'run.py'), join(here, 'scenarios.json'), spec, work], { cwd: repo, encoding: 'utf8', maxBuffer: 1 << 28 });
  if (py.status !== 0) throw new Error(`the Python runner failed:\n${py.stderr}`);
  process.exitCode = compare(reference, JSON.parse(py.stdout)) ? 0 : 1;
} finally {
  rmSync(work, { recursive: true, force: true });
}

async function runReference() {
  const now = new Date(config.now);
  const sha = (s) => createHash('sha256').update(s ?? '').digest('hex').slice(0, 16);
  const cache = new Map();
  const out = [];
  for (const sc of config.scenarios) {
    const library = new reader.Library({ clock: () => now });
    const codes = [];
    for (const [key, sidecar] of sc.load) {
      const path = join(spec, config.packages[key]);
      if (!cache.has(path)) cache.set(path, await reader.readPackage(path));
      const result = cache.get(path);
      let bound = {};
      if (sidecar) {
        const b = reader.bindSidecar(join(work, sidecar), result);
        codes.push(...b.diagnostics.map((d) => d.code));
        if (b.usable) bound = { chunks: b.chunks, index: b.index };
      }
      library.add(result, bound);
    }
    const embedder = hashing(sc.embedder === 'other' ? 'another-model' : 'parity-hash');
    const dense = () => new reader.DenseBackend(library, { embedder });
    let backend;
    let search;
    if (sc.backend.startsWith('store')) {
      backend = await new reader.MemoryStoreBackend(sc.backend === 'store-dense' ? { embedder } : {}).ingest(library);
      search = new reader.Search({ packages: library.packages.map((p) => reader.packageState(p.result)), clock: () => now }, { backend, audiences: sc.audiences });
    } else {
      backend = sc.backend === 'dense' ? dense()
        : sc.backend === 'hybrid' ? new reader.HybridBackend({ lexical: new reader.LexicalBackend(library), dense: dense(), ...(sc.hybrid ?? {}) })
          : new reader.LexicalBackend(library);
      search = new reader.Search(library, { backend, audiences: sc.audiences, ...(sc.diversify ? { hooks: reader.diversify({ perNode: sc.diversify }) } : {}) });
    }
    const queries = [];
    for (const q of config.queries[sc.queries]) {
      const records = await search.search(q, { limit: config.limit, ...(sc.locale ? { locale: sc.locale } : {}) });
      queries.push({ query: q, results: records.map((r) => ({ ref: r.node.ref, locale: r.node.locale ?? null, span: r.span ? [r.span.start, r.span.end] : null, score: r.score, text: sha(r.text) })) });
    }
    codes.push(...(backend.diagnostics ?? []).map((d) => d.code));
    out.push({ name: sc.name, codes: [...new Set(codes)].sort(), queries });
  }
  return out;
}

function compare(reference, python) {
  let ok = true;
  let queries = 0;
  for (const [i, a] of reference.entries()) {
    const b = python[i];
    if (JSON.stringify(a.codes) !== JSON.stringify(b?.codes)) {
      console.error(`DIFF ${a.name}: codes ${a.codes} vs ${b?.codes}`);
      ok = false;
    }
    for (const [j, qa] of a.queries.entries()) {
      queries++;
      const qb = b?.queries[j];
      if (JSON.stringify(qa.results) === JSON.stringify(qb?.results)) continue;
      ok = false;
      console.error(`DIFF ${a.name} | "${qa.query}"\n  reference: ${JSON.stringify(qa.results)}\n  Python:    ${JSON.stringify(qb?.results)}`);
    }
  }
  console.log(ok ? `Parity: ${queries} queries in ${reference.length} scenarios return the same records, order, spans, text and scores.` : 'Parity failed.');
  return ok;
}
