#!/usr/bin/env node
/*
 * Post-merge qualification fixture generator (#110).
 * Generating synthetic inputs is NOT running a benchmark and does not prove
 * 100k/250k full-scan support. It must not be executed in ordinary CI.
 */
import { createHash } from 'node:crypto';
import { mkdir, open, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

const count = Number(process.argv[2]);
const kind = process.argv[3];
const suppliedRoot = process.argv[4];

if (process.env.TOOLIP_LARGE_FIXTURE_OPT_IN !== 'yes')
  throw new Error('Explicit TOOLIP_LARGE_FIXTURE_OPT_IN=yes is required.');
if (![100_000, 250_000].includes(count))
  throw new Error('Post-merge fixture size must be exactly 100000 or 250000.');
if (kind !== 'files' && kind !== 'graph')
  throw new Error('Fixture kind must be files or graph.');
if (!suppliedRoot || !path.isAbsolute(suppliedRoot))
  throw new Error('Fixture output must be an explicit absolute directory.');
const parent = await realpath(path.dirname(suppliedRoot));
const destination = path.resolve(suppliedRoot);
if (destination === parent || destination === path.parse(destination).root ||
    path.basename(destination).startsWith('.'))
  throw new Error('Fixture destination is unsafe.');
// The directory must not exist. Never overwrite production files or a
// partially generated fixture from an earlier attempt.
await mkdir(destination, { mode: 0o700 });
let completed = false;
const hash = createHash('sha256');
const record = (file, bytes) => {
  hash.update(file).update('\0').update(bytes).update('\0');
};
let fileBytes = 0;
let edges = 0;
try {
  if (kind === 'files') {
    const source = path.join(destination, 'src');
    await mkdir(source, { mode: 0o700 });
    const pending = new Set();
    const concurrency = 16;
    for (let index = 0; index < count; index++) {
      const group = String(Math.floor(index / 1_000)).padStart(4, '0');
      const folder = path.join(source, group);
      if (index % 1_000 === 0)
        await mkdir(folder, { mode: 0o700 });
      const name = `source-${String(index).padStart(6, '0')}.ts`;
      // A deliberately harmless, deterministic body; a limited fixed
      // rule seed is included for first-finding and false-clean checks.
      const body = index % 10_000 === 0
        ? `export const seeded${index}=eval('2+2');\n`
        : `export const fixture${index}=${index};\n`;
      const relative = `src/${group}/${name}`;
      const bytes = Buffer.from(body);
      fileBytes += bytes.byteLength;
      record(relative, bytes);
      const operation = writeFile(path.join(folder, name), bytes, {
        flag: 'wx', mode: 0o600
      }).finally(() => pending.delete(operation));
      pending.add(operation);
      if (pending.size >= concurrency) await Promise.race(pending);
    }
    await Promise.all(pending);
  } else {
    const output = await open(path.join(destination, 'exact-graph.jsonl'),
      'wx', 0o600);
    try {
      for (let index = 0; index < count; index++) {
        // Exact instance identities, with multi-version cases and a bounded
        // converging out-degree. JSONL represents synthetic graph topology,
        // NOT a validated package-lock or a full dependency scan.
        const item = {
          id: `npm:fixture-${String(index % 50000).padStart(6, '0')}@1.${index % 1000}.${Math.floor(index / 1000)}:${index}`,
          ecosystem: 'npm',
          instance: index,
          dependencies: index + 2 < count
            ? [index + 1, index + 2]
            : index + 1 < count ? [index + 1] : []
        };
        edges += item.dependencies.length;
        const line = JSON.stringify(item) + '\n';
        const bytes = Buffer.from(line);
        fileBytes += bytes.length;
        record(`instance-${index}`, bytes);
        await output.write(bytes);
      }
    } finally {
      await output.close();
    }
  }
  const result = {
    schema: 'toolip.dev/large-fixture/v1',
    intendedPhase: 'post-merge',
    scope: kind === 'graph' ? 'isolated-synthetic-graph-only' : 'synthetic-source-files',
    count,
    bytes: fileBytes,
    exactGraphVertices: kind === 'graph' ? count : null,
    exactGraphEdges: kind === 'graph' ? edges : null,
    seededSourceFiles: kind === 'files' ? Math.ceil(count / 10_000) : null,
    fixtureSha256: hash.digest('hex'),
    benchmarksExecuted: false,
    fullSecurityScanPerformed: false,
    label: 'not-qualified'
  };
  await writeFile(path.join(destination, 'fixture-manifest.json'),
    JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  completed = true;
  console.log(JSON.stringify(result));
} finally {
  if (!completed) await rm(destination, { recursive: true, force: true });
}
