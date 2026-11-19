import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  createProjectSnapshot,
  type ProjectSnapshot
} from '../src/application/project-snapshot.js';
import { AnalysisResultCache } from '../src/application/task-scheduler.js';
import { buildSecurityScorecard } from '../src/application/security-scorecard.js';
import { runGitChecked } from '../src/core/git/safe-git.js';
import { createScannerContext } from '../src/core/scanner-context.js';

function boundedInteger(
  value: string | undefined,
  fallback: number,
  maximum: number,
  name: string
): number {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum)
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  return parsed;
}

const iterations = boundedInteger(
  process.env.SOAK_ITERATIONS,
  40,
  500,
  'SOAK_ITERATIONS'
);
const sourceFiles = boundedInteger(
  process.env.SOAK_FILES,
  100,
  2_000,
  'SOAK_FILES'
);
const maxRssBytes =
  boundedInteger(process.env.SOAK_MAX_RSS_MB, 1_024, 4_096, 'SOAK_MAX_RSS_MB') *
  1024 *
  1024;

const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-analysis-soak-'));
const expectedFiles = sourceFiles + 2;
const cache = new AnalysisResultCache(Math.max(128, sourceFiles * 4));
let previousSnapshot: ProjectSnapshot | undefined;
const durations: number[] = [];
let peakRssBytes = process.memoryUsage().rss;
let totalSnapshotReads = 0;
let totalSnapshotReuses = 0;
let totalCacheHits = 0;
let totalCacheMisses = 0;
let totalResultCacheHits = 0;
let totalResultCacheMisses = 0;
let totalResultCacheEvictions = 0;
let peakRetainedCacheBytes = 0;

try {
  await writeFile(
    path.join(root, 'package.json'),
    JSON.stringify({ name: 'toolip-analysis-soak', version: '1.0.0' })
  );
  await writeFile(
    path.join(root, 'package-lock.json'),
    JSON.stringify({
      name: 'toolip-analysis-soak',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': { name: 'toolip-analysis-soak', version: '1.0.0' }
      }
    })
  );
  for (let index = 0; index < sourceFiles; index += 1) {
    const name = `source-${index.toString().padStart(5, '0')}.ts`;
    await writeFile(
      path.join(root, name),
      `export const soakValue${index} = ${index};\n`
    );
  }
  await runGitChecked(['init', '--quiet'], { cwd: root });
  await runGitChecked(['add', '-A'], { cwd: root });

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const changedIndex = iteration % sourceFiles;
    const changedPath = `source-${changedIndex.toString().padStart(5, '0')}.ts`;
    await writeFile(
      path.join(root, changedPath),
      `export const soakValue${changedIndex} = ${sourceFiles + iteration};\n`
    );

    const started = performance.now();
    const scannerContext = await createScannerContext(root, {
      maxFiles: expectedFiles
    });
    const snapshot = await createProjectSnapshot(root, {
      discoveredFiles: scannerContext.files,
      previous: previousSnapshot,
      maxFiles: expectedFiles,
      maxFileBytes: 4_096,
      maxTotalBytes: expectedFiles * 4_096
    });
    const result = await buildSecurityScorecard(
      root,
      {},
      {
        scannerContext,
        projectSnapshot: snapshot,
        previousSnapshot,
        analysisCache: cache,
        offline: true,
        budget: { totalMs: 30_000 },
        includePackageHealth: false
      }
    );
    const elapsedMs = performance.now() - started;
    durations.push(elapsedMs);
    previousSnapshot = snapshot;

    if (
      scannerContext.summary.totalFiles !== expectedFiles ||
      result.analysis.state !== 'complete' ||
      result.coverage.state !== 'complete'
    ) {
      throw new Error(
        `iteration ${iteration} was incomplete: ${JSON.stringify({
          discovered: scannerContext.summary.totalFiles,
          analysis: result.analysis,
          coverage: result.coverage
        })}`
      );
    }
    if (
      iteration > 0 &&
      (snapshot.metrics.filesRead < 1 ||
        snapshot.metrics.filesReused < expectedFiles - 1)
    ) {
      throw new Error(
        `iteration ${iteration} did not reuse unchanged snapshot files`
      );
    }

    totalSnapshotReads += snapshot.metrics.filesRead;
    totalSnapshotReuses += snapshot.metrics.filesReused;
    totalCacheHits += result.cacheMetrics.hits;
    totalCacheMisses += result.cacheMetrics.misses;
    totalResultCacheHits += result.cacheMetrics.resultCache.hits;
    totalResultCacheMisses += result.cacheMetrics.resultCache.misses;
    totalResultCacheEvictions += result.cacheMetrics.resultCache.evictions;
    peakRetainedCacheBytes = Math.max(
      peakRetainedCacheBytes,
      result.cacheMetrics.resultCache.retainedSerializedBytes
    );
    peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
    if (peakRssBytes > maxRssBytes)
      throw new Error(`RSS budget exceeded at iteration ${iteration}`);
  }

  const ordered = [...durations].sort((left, right) => left - right);
  const percentile = (fraction: number): number =>
    Math.round((ordered[Math.ceil(ordered.length * fraction) - 1] ?? 0) * 100) /
    100;
  process.stdout.write(
    `${JSON.stringify({
      schemaVersion: 1,
      fixture: 'offline-scorecard-snapshot-invalidation-soak',
      iterations,
      sourceFiles,
      expectedFiles,
      platform: process.platform,
      node: process.version,
      p50Ms: percentile(0.5),
      p95Ms: percentile(0.95),
      maxMs: Math.round(Math.max(...durations) * 100) / 100,
      peakRssBytes,
      maxRssBytes,
      snapshotFilesRead: totalSnapshotReads,
      snapshotFilesReused: totalSnapshotReuses,
      analysisCacheHits: totalCacheHits,
      analysisCacheMisses: totalCacheMisses,
      resultCacheHits: totalResultCacheHits,
      resultCacheMisses: totalResultCacheMisses,
      resultCacheEvictions: totalResultCacheEvictions,
      peakRetainedCacheBytes,
      analysisComplete: true,
      coverageComplete: true,
      externalProviderRequests: 0
    })}\n`
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
