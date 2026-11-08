import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { buildDependencyTree } from '../src/core/dependency-tree.js';
import { walkProjectFiles } from '../src/core/file-walker.js';
import { TextFileReader } from '../src/core/text-file-reader.js';
import { indexSourceDirectoryChildren } from '../src/analyzers/ast/source-analysis.js';
import {
  createProjectSnapshot,
  type ProjectSnapshot
} from '../src/application/project-snapshot.js';
import { AnalysisResultCache } from '../src/application/task-scheduler.js';
import { createScannerContext } from '../src/core/scanner-context.js';
import { buildSecurityScorecard } from '../src/application/security-scorecard.js';
import { runGitChecked } from '../src/core/git/safe-git.js';
import {
  findSecretMatches,
  secretFingerprint
} from '../src/core/secret-utils.js';

const defaultSizes = [1_000, 10_000, 50_000];
const workerIndex = process.argv.indexOf('--worker');
const workerFixture =
  workerIndex >= 0 ? process.argv[workerIndex + 1] : undefined;
const workerSize =
  workerIndex >= 0 ? Number(process.argv[workerIndex + 2]) : undefined;
const requestedSizes =
  workerIndex >= 0 ? [] : process.argv.slice(2).map(Number);
const sizes = requestedSizes.length > 0 ? requestedSizes : defaultSizes;
if (
  sizes.some((size) => !Number.isSafeInteger(size) || size < 1 || size > 50_000)
) {
  throw new Error('benchmark sizes must be safe integers between 1 and 50,000');
}

type Measurement<T> = {
  wallMs: number;
  userCpuMs: number;
  systemCpuMs: number;
  heapDeltaBytes: number;
  heapPeakBytes: number;
  rssDeltaBytes: number;
  rssPeakBytes: number;
  result: T;
};

async function measure<T>(
  operation: () => Promise<T>
): Promise<Measurement<T>> {
  const before = process.memoryUsage();
  const cpuBefore = process.cpuUsage();
  let heapPeakBytes = before.heapUsed;
  let rssPeakBytes = before.rss;
  const sample = (): void => {
    const usage = process.memoryUsage();
    heapPeakBytes = Math.max(heapPeakBytes, usage.heapUsed);
    rssPeakBytes = Math.max(rssPeakBytes, usage.rss);
  };
  const timer = setInterval(sample, 5);
  timer.unref();
  const started = performance.now();
  try {
    const result = await operation();
    sample();
    const elapsed = performance.now() - started;
    const cpu = process.cpuUsage(cpuBefore);
    const after = process.memoryUsage();
    return {
      wallMs: Math.round(elapsed * 100) / 100,
      userCpuMs: Math.round((cpu.user / 1_000) * 100) / 100,
      systemCpuMs: Math.round((cpu.system / 1_000) * 100) / 100,
      heapDeltaBytes: after.heapUsed - before.heapUsed,
      heapPeakBytes,
      rssDeltaBytes: after.rss - before.rss,
      rssPeakBytes,
      result
    };
  } finally {
    clearInterval(timer);
  }
}

function emit(
  fixture: string,
  size: number,
  pass: string,
  data: unknown
): void {
  process.stdout.write(
    `${JSON.stringify({
      schemaVersion: 1,
      fixture,
      size,
      pass,
      platform: process.platform,
      node: process.version,
      gitSha: process.env.GIT_COMMIT ?? 'working-tree',
      measurementScope:
        process.env.TOOLIP_BENCHMARK_ISOLATED === 'true'
          ? 'isolated-fixture-process'
          : 'process',
      providerRequests: 0,
      ...data
    })}\n`
  );
}

async function benchmarkLockfile(
  size: number,
  shape: 'wide' | 'converging'
): Promise<void> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-graph-benchmark-'));
  try {
    const packages: Record<
      string,
      {
        name: string;
        version: string;
        dependencies?: Record<string, string>;
      }
    > = {};
    const rootDependencies: Record<string, string> = {};
    for (let index = 0; index < size; index += 1) {
      const name = `fixture-${index.toString().padStart(6, '0')}`;
      if (shape === 'wide') rootDependencies[name] = `1.${index % 100}.0`;
      const dependencies: Record<string, string> = {};
      if (shape === 'converging') {
        for (const offset of [1, 2]) {
          const child = index + offset;
          if (child < size) {
            dependencies[`fixture-${child.toString().padStart(6, '0')}`] =
              `1.${child % 100}.0`;
          }
        }
      }
      packages[`node_modules/${name}`] = {
        name,
        version: `1.${index % 100}.0`,
        ...(Object.keys(dependencies).length > 0 ? { dependencies } : {})
      };
    }
    if (shape === 'converging') {
      for (const index of [0, 1]) {
        rootDependencies[`fixture-${index.toString().padStart(6, '0')}`] =
          `1.${index % 100}.0`;
      }
    }
    packages[''] = {
      name: 'benchmark-fixture',
      version: '1.0.0',
      dependencies: rootDependencies
    };
    const lockfile = {
      name: 'benchmark-fixture',
      lockfileVersion: 3,
      packages
    };
    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify(lockfile)
    );

    for (const pass of ['cold', 'warm'] as const) {
      const measurement = await measure(() => buildDependencyTree(root));
      const expectedDirect = shape === 'wide' ? size : Math.min(size, 2);
      const expectedReachable = size;
      if (
        measurement.result.summary.direct !== expectedDirect ||
        measurement.result.summary.transitive !==
          expectedReachable - expectedDirect ||
        (shape === 'converging' &&
          measurement.result.summary.maxDepth !== Math.max(1, size))
      ) {
        throw new Error(`unexpected ${shape} graph summary at size ${size}`);
      }
      emit(`npm-lock-${shape}`, size, pass, {
        ...measurement,
        result: measurement.result.summary,
        filesOpened: 1,
        graphEdges: shape === 'wide' ? size : Math.max(0, (size - 1) * 2)
      });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function createSourceFixture(root: string, size: number): Promise<void> {
  const body = 'export const fixtureValue = "bounded-source-fixture";\n';
  const batchSize = 128;
  for (let offset = 0; offset < size; offset += batchSize) {
    const end = Math.min(size, offset + batchSize);
    await Promise.all(
      Array.from({ length: end - offset }, (_, relative) => {
        const index = offset + relative;
        const name = `source-${index.toString().padStart(6, '0')}.ts`;
        return writeFile(path.join(root, name), body);
      })
    );
  }
}

async function readFixture(
  root: string,
  files: Awaited<ReturnType<typeof walkProjectFiles>>
) {
  const bodyBytes = 57;
  const reader = new TextFileReader(
    {
      maxFiles: files.length,
      maxFileBytes: 4_096,
      maxTotalBytes: Math.max(1, files.length * bodyBytes * 2)
    },
    { root }
  );
  const batchSize = 128;
  for (let offset = 0; offset < files.length; offset += batchSize) {
    const batch = files.slice(offset, offset + batchSize);
    const results = await Promise.all(
      batch.map((file) =>
        reader.read(file.absolutePath, undefined, file.snapshot)
      )
    );
    if (results.some((result) => result.status !== 'ok')) {
      throw new Error(`source-tree read was incomplete at ${offset}`);
    }
  }
  return reader.usage;
}

async function benchmarkSourceTree(size: number): Promise<void> {
  const root = await mkdtemp(
    path.join(os.tmpdir(), 'toolip-source-benchmark-')
  );
  try {
    await createSourceFixture(root, size);
    let files: Awaited<ReturnType<typeof walkProjectFiles>> = [];
    for (const pass of ['cold', 'warm'] as const) {
      const measurement = await measure(async () => {
        files = await walkProjectFiles(root, { maxFiles: size });
        if (files.length !== size)
          throw new Error(`expected ${size} files, discovered ${files.length}`);
        return readFixture(root, files);
      });
      emit('source-tree-walk-and-bounded-read', size, pass, {
        ...measurement,
        result: measurement.result,
        filesDiscovered: files.length,
        filesOpened: measurement.result.filesRead,
        bytesRead: measurement.result.bytesRead
      });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function benchmarkAstDirectoryIndex(size: number): Promise<void> {
  const root = path.resolve(os.tmpdir(), `toolip-ast-directory-${size}`);
  const directories = new Set<string>([root, path.join(root, 'src')]);
  for (let index = 0; index < size; index += 1) {
    directories.add(path.join(root, 'src', `module-${index}`));
  }
  const queries = [...directories].slice(1);

  const indexed = await measure(async () => {
    const childrenByDirectory = indexSourceDirectoryChildren(directories);
    const returnedChildren = queries.reduce(
      (total, directory) =>
        total + (childrenByDirectory.get(directory)?.size ?? 0),
      0
    );
    return {
      directoryCount: directories.size,
      queryCount: queries.length,
      indexVisits: directories.size,
      returnedChildren
    };
  });
  emit('ast-source-directory-indexed', size, 'indexed', {
    ...indexed,
    result: indexed.result,
    directoriesIndexed: indexed.result.directoryCount,
    directoryQueries: indexed.result.queryCount
  });

  if (size <= 10_000) {
    const legacy = await measure(async () => {
      let candidateVisits = 0;
      let returnedChildren = 0;
      for (const query of queries) {
        const children = new Set<string>();
        for (const directory of directories) {
          candidateVisits += 1;
          const relative = path.relative(query, directory);
          if (
            !relative ||
            path.isAbsolute(relative) ||
            relative.startsWith('..')
          )
            continue;
          const first = relative.split(path.sep)[0];
          if (first) children.add(path.join(query, first));
        }
        returnedChildren += children.size;
      }
      return {
        directoryCount: directories.size,
        queryCount: queries.length,
        candidateVisits,
        returnedChildren
      };
    });
    emit('ast-source-directory-full-scan-reference', size, 'baseline', {
      ...legacy,
      result: legacy.result,
      directoriesScanned: legacy.result.directoryCount,
      directoryQueries: legacy.result.queryCount,
      baselineRevision: '41a3a9319b19bfb2c2290bafd1bb9fab794ddcd0'
    });
  } else {
    emit('ast-source-directory-full-scan-reference', size, 'skipped', {
      reason: 'legacy directory scan is quadratic and capped at 10,000 queries',
      baselineRevision: '41a3a9319b19bfb2c2290bafd1bb9fab794ddcd0'
    });
  }
}

/** Full bounded doctor pass over a generated repository tree, cold and warm. */
async function benchmarkRepositoryScan(
  size: number,
  useAnalysisCache = true,
  passes: readonly ('cold' | 'warm' | 'incremental')[] = [
    'cold',
    'warm',
    'incremental'
  ]
): Promise<void> {
  const root = await mkdtemp(
    path.join(os.tmpdir(), 'toolip-repository-benchmark-')
  );
  const expectedFiles = size + 3;
  const maximumTotalBytes = Math.max(1, expectedFiles * 4_096);
  const analysisCache = useAnalysisCache
    ? new AnalysisResultCache(Math.max(1, size * 2))
    : undefined;
  const fixtureName = useAnalysisCache
    ? 'repository-security-scorecard-full-pass'
    : 'repository-security-scorecard-no-analysis-cache';
  let previousSnapshot: ProjectSnapshot | undefined;
  try {
    await createSourceFixture(root, size);
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ name: 'toolip-benchmark-fixture', version: '1.0.0' })
    );
    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        name: 'toolip-benchmark-fixture',
        version: '1.0.0',
        lockfileVersion: 3,
        requires: true,
        packages: {
          '': { name: 'toolip-benchmark-fixture', version: '1.0.0' }
        }
      })
    );
    await writeFile(
      path.join(root, '.gitignore'),
      '.env*\n*.pem\n*.key\nnode_modules/\n'
    );
    await runGitChecked(['init'], { cwd: root });
    await runGitChecked(['add', '-A'], { cwd: root });
    for (const pass of passes) {
      if (pass === 'incremental')
        await writeFile(
          path.join(root, 'source-000000.ts'),
          'export const fixtureValue = "incremental-source-fixture";\n'
        );
      const measurement = await measure(async () => {
        const context = await createScannerContext(root, {
          maxFiles: expectedFiles
        });
        const snapshot = await createProjectSnapshot(root, {
          discoveredFiles: context.files,
          previous: previousSnapshot,
          maxFiles: expectedFiles,
          maxFileBytes: 4_096,
          maxTotalBytes: maximumTotalBytes
        });
        const scorecard = await buildSecurityScorecard(
          root,
          {},
          {
            scannerContext: context,
            snapshot,
            projectSnapshot: snapshot,
            analysisCache,
            offline: true,
            budget: {
              maxFiles: expectedFiles,
              maxFileBytes: 4_096,
              maxTotalBytes: maximumTotalBytes
            }
          }
        );
        if (
          scorecard.analysis.state !== 'complete' ||
          scorecard.coverage.state !== 'complete' ||
          context.summary.totalFiles !== expectedFiles
        ) {
          throw new Error(
            `full repository scan was incomplete at ${size} source files: ${JSON.stringify(scorecard.analysis)}`
          );
        }
        previousSnapshot = snapshot;
        return {
          snapshotReads: snapshot.metrics.filesRead,
          snapshotBytesRead: snapshot.metrics.bytesRead,
          snapshotFilesReused: snapshot.metrics.filesReused,
          cacheHits: scorecard.cacheMetrics.hits,
          cacheMisses: scorecard.cacheMetrics.misses,
          astProjectCacheHits: scorecard.cacheMetrics.astProjectHits,
          astProjectCacheMisses: scorecard.cacheMetrics.astProjectMisses,
          findings: scorecard.findings.length,
          filesDiscovered: context.summary.totalFiles,
          scorecardState: scorecard.analysis.state,
          coverage: scorecard.coverage
        };
      });
      emit(fixtureName, size, pass, {
        ...measurement,
        result: measurement.result,
        filesOpened: measurement.result.snapshotReads,
        bytesRead: measurement.result.snapshotBytesRead,
        cacheHits: measurement.result.cacheHits,
        cacheMisses: measurement.result.cacheMisses,
        astProjectCacheHits: measurement.result.astProjectCacheHits,
        astProjectCacheMisses: measurement.result.astProjectCacheMisses
      });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

/** Two simultaneous offline scorecards over one immutable repository snapshot. */
async function benchmarkConcurrentRepositoryScans(size: number): Promise<void> {
  const root = await mkdtemp(
    path.join(os.tmpdir(), 'toolip-concurrent-repository-benchmark-')
  );
  const expectedFiles = size + 3;
  const maximumTotalBytes = Math.max(1, expectedFiles * 4_096);
  try {
    await createSourceFixture(root, size);
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'toolip-concurrent-benchmark-fixture',
        version: '1.0.0'
      })
    );
    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        name: 'toolip-concurrent-benchmark-fixture',
        version: '1.0.0',
        lockfileVersion: 3,
        requires: true,
        packages: {
          '': { name: 'toolip-concurrent-benchmark-fixture', version: '1.0.0' }
        }
      })
    );
    await writeFile(
      path.join(root, '.gitignore'),
      '.env*\n*.pem\n*.key\nnode_modules/\n'
    );
    await runGitChecked(['init'], { cwd: root });
    await runGitChecked(['add', '-A'], { cwd: root });
    const context = await createScannerContext(root, {
      maxFiles: expectedFiles
    });
    const snapshot = await createProjectSnapshot(root, {
      discoveredFiles: context.files,
      maxFiles: expectedFiles,
      maxFileBytes: 4_096,
      maxTotalBytes: maximumTotalBytes
    });
    const measurement = await measure(async () => {
      const results = await Promise.all(
        [0, 1].map(() =>
          buildSecurityScorecard(
            root,
            {},
            {
              scannerContext: context,
              snapshot,
              projectSnapshot: snapshot,
              analysisCache: new AnalysisResultCache(Math.max(1, size * 2)),
              offline: true,
              budget: {
                maxFiles: expectedFiles,
                maxFileBytes: 4_096,
                maxTotalBytes: maximumTotalBytes
              }
            }
          )
        )
      );
      if (
        results.some(
          (scorecard) =>
            scorecard.analysis.state !== 'complete' ||
            scorecard.coverage.state !== 'complete' ||
            scorecard.coverage.scanned !== expectedFiles
        )
      )
        throw new Error(`concurrent scorecard was incomplete at ${size} files`);
      return results.map((scorecard) => ({
        findings: scorecard.findings.length,
        analysis: scorecard.analysis.state,
        coverage: scorecard.coverage.state,
        scanned: scorecard.coverage.scanned,
        astProjectCacheMisses: scorecard.cacheMetrics.astProjectMisses
      }));
    });
    emit('repository-security-scorecard-concurrent-pair', size, 'cold', {
      ...measurement,
      result: measurement.result,
      concurrentScans: 2,
      filesPerScan: expectedFiles,
      providerRequests: 0
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function benchmarkText(size: number): {
  content: string;
  pattern: RegExp;
} {
  const content = Array.from({ length: size }, (_, index) =>
    index % 5 === 0 ? `TOKEN_${index}\n` : `line_${index}\n`
  ).join('');
  return { content, pattern: /TOKEN_\d+/g };
}

async function benchmarkSecretLocations(size: number): Promise<void> {
  const { content, pattern } = benchmarkText(size);
  const optimized = await measure(async () => {
    const matches = findSecretMatches(content, pattern);
    return {
      matches: matches.length,
      locationChecksum: matches.reduce(
        (sum, match) =>
          sum + match.line + match.column + match.fingerprint.charCodeAt(0),
        0
      )
    };
  });
  emit('secret-locations-optimized', size, 'single-pass', {
    ...optimized,
    result: optimized.result,
    sourceBytes: Buffer.byteLength(content)
  });

  // This reference reproduces the previous prefix split per match. Keep its
  // scale bounded because its purpose is to expose the old quadratic growth.
  if (size <= 10_000) {
    const legacy = await measure(async () => {
      let matches = 0;
      let locationChecksum = 0;
      for (const match of content.matchAll(pattern)) {
        const value = match[0];
        const index = match.index ?? 0;
        const before = content.slice(0, index);
        const lastNewline = before.lastIndexOf('\n');
        const line = before.split('\n').length;
        const column = index - lastNewline;
        locationChecksum +=
          line + column + secretFingerprint(value).charCodeAt(0);
        matches += 1;
      }
      return { matches, locationChecksum };
    });
    emit('secret-locations-legacy-prefix-split-reference', size, 'baseline', {
      ...legacy,
      result: legacy.result,
      sourceBytes: Buffer.byteLength(content),
      baselineRevision: 'cf94e2103e7d2ced05a0acf68251bcc8fd7ab125'
    });
  } else {
    emit('secret-locations-legacy-prefix-split-reference', size, 'skipped', {
      reason: 'legacy O(n*m) reference is capped at 10,000 lines',
      baselineRevision: 'cf94e2103e7d2ced05a0acf68251bcc8fd7ab125'
    });
  }
}

async function runWorker(fixture: string, size: number): Promise<void> {
  switch (fixture) {
    case 'secret-locations':
      await benchmarkSecretLocations(size);
      break;
    case 'source-tree':
      await benchmarkSourceTree(size);
      break;
    case 'ast-directory-index':
      await benchmarkAstDirectoryIndex(size);
      break;
    case 'repository-scorecard':
      await benchmarkRepositoryScan(size);
      break;
    case 'repository-scorecard-cold-cache':
      await benchmarkRepositoryScan(size, true, ['cold']);
      break;
    case 'repository-scorecard-no-cache':
      await benchmarkRepositoryScan(size, false, ['cold']);
      break;
    case 'repository-scorecard-concurrent':
      await benchmarkConcurrentRepositoryScans(size);
      break;
    case 'npm-lock-wide':
      await benchmarkLockfile(size, 'wide');
      break;
    case 'npm-lock-converging':
      await benchmarkLockfile(size, 'converging');
      break;
    default:
      throw new Error(`unknown benchmark worker fixture: ${fixture}`);
  }
}

if (workerIndex >= 0) {
  if (
    !workerFixture ||
    !Number.isSafeInteger(workerSize) ||
    (workerSize ?? 0) < 1 ||
    (workerSize ?? 0) > 50_000
  )
    throw new Error('benchmark worker requires a fixture name and size');
  await runWorker(workerFixture, workerSize);
} else {
  const scriptPath = path.resolve(
    process.argv[1] ?? 'scripts/benchmark-dependency-graph.ts'
  );
  for (const size of sizes) {
    for (const fixture of [
      'secret-locations',
      'source-tree',
      'ast-directory-index',
      'repository-scorecard',
      'repository-scorecard-concurrent',
      'npm-lock-wide',
      'npm-lock-converging'
    ]) {
      const child = spawnSync(
        process.execPath,
        ['--import', 'tsx', scriptPath, '--worker', fixture, String(size)],
        {
          cwd: process.cwd(),
          encoding: 'utf8',
          env: { ...process.env, TOOLIP_BENCHMARK_ISOLATED: 'true' },
          timeout: 600_000,
          maxBuffer: 8 * 1024 * 1024
        }
      );
      if (child.stdout) process.stdout.write(child.stdout);
      if (child.stderr) process.stderr.write(child.stderr);
      if (child.error) throw child.error;
      if (child.status !== 0)
        throw new Error(
          `benchmark worker ${fixture} at ${size} exited with ${String(child.status)}`
        );
    }
  }
}
