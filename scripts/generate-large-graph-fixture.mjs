#!/usr/bin/env node
/*
 * Streaming large-graph fixture generator (#86). File generation is NOT a
 * benchmark run, security scan or release qualification. The 5M/10M modes
 * require explicit independent opt-in to avoid accidental disk exhaustion.
 *
 * Synthetic adjacency JSONL models installed package INSTANCE topology. It
 * deliberately does not claim to be a valid npm, Cargo or Maven lockfile or
 * to exercise every security analyzer.
 */
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, lstat, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { once } from 'node:events';

const allowedSizes = new Set([500_000, 1_000_000, 2_000_000, 5_000_000, 10_000_000]);
const size = Number(process.argv[2]);
const output = process.argv[3];
const shape = process.argv[4] ?? 'converging';
const maximumBytes = 3_000_000_000;

if (process.env.TOOLIP_HUGE_GRAPH_OPT_IN !== 'yes')
  throw new Error('TOOLIP_HUGE_GRAPH_OPT_IN=yes must be explicitly supplied.');
if (!Number.isSafeInteger(size) || !allowedSizes.has(size))
  throw new Error('Choose an exact 500k, 1M, 2M, 5M or 10M instance count.');
if (!['wide', 'converging', 'chain', 'isolated'].includes(shape))
  throw new Error('Fixture graph shape must be wide, converging, chain or isolated.');
if (!output || !path.isAbsolute(output) ||
    output === path.parse(output).root)
  throw new Error('Output must be an absolute new non-root directory.');
if (size >= 5_000_000 && process.env.TOOLIP_STRESS_FIXTURE_OPT_IN !== 'yes')
  throw new Error('5M/10M experimental stress fixtures require separate stress opt-in.');

let created = false;
let completed = false;
const destination = path.resolve(output);
try {
  await mkdir(destination, { mode: 0o700 });
  created = true;
  const file = path.join(destination, 'dependency-instances.jsonl');
  const stream = createWriteStream(file, { flags: 'wx', mode: 0o600, highWaterMark: 64 * 1024 });
  const digest = createHash('sha256');
  let bytes = 0;
  let edges = 0;
  let emitted = 0;
  const write = async (line) => {
    const chunk = Buffer.from(line + '\n', 'utf8');
    bytes += chunk.length;
    if (bytes > maximumBytes)
      throw new Error('Fixture generation hit the 3 GB disk budget.');
    digest.update(chunk);
    if (!stream.write(chunk)) await once(stream, 'drain');
  };
  try {
    for (let index = 0; index < size; index++) {
      let dependencies = [];
      if (shape === 'chain') {
        if (index + 1 < size) dependencies = [index + 1];
      } else if (shape === 'converging') {
        if (index + 1 < size) dependencies.push(index + 1);
        if (index + 2 < size) dependencies.push(index + 2);
      } else if (shape === 'wide' && index === 0) {
        // A single huge array would violate the memory bound. Represent
        // wide fan-out as separate edge records later in the same stream.
        dependencies = [];
      }
      edges += dependencies.length;
      const item = {
        type: 'package',
        id: index,
        packageName: `fixture-${String(index % 200_000).padStart(6, '0')}`,
        version: `1.${index % 1000}.${Math.floor(index / 1000)}`,
        instance: index,
        dependencies
      };
      await write(JSON.stringify(item));
      emitted++;
    }
    if (shape === 'wide') {
      for (let index = 1; index < size; index++) {
        await write(JSON.stringify({ type: 'edge', from: 0, to: index }));
        edges++;
      }
    }
    stream.end();
    await once(stream, 'finish');
  } catch (error) {
    stream.destroy();
    throw error;
  }

  const manifest = {
    schema: 'toolip.dev/large-graph-fixture/v1',
    size: emitted,
    edges,
    shape,
    bytes,
    fixtureSha256: digest.digest('hex'),
    generatedWithoutSourceExecution: true,
    securityScanPerformed: false,
    benchmarkPerformed: false,
    passedReleaseQualification: false,
    claimedResourceBounds: {
      streamedRecords: true,
      maximumOutputBytes: maximumBytes,
      scanMemoryMeasured: false
    },
    phase: size >= 5_000_000 ? 'experimental-stress' : 'qualification-candidate'
  };
  await writeFile(path.join(destination, 'fixture-manifest.json'),
    JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  completed = true;
  console.log(JSON.stringify(manifest));
} finally {
  if (created && !completed)
    await rm(destination, { recursive: true, force: true });
}
