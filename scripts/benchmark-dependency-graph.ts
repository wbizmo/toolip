import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { PerformanceObserver } from 'node:perf_hooks';
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
const defaultSourceBody =
  'export const fixtureValue = "bounded-source-fixture";\n';
function boundedEnvironmentInteger(
  name: string,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(
      `${name} must be an integer between ${minimum} and ${maximum}`
    );
  }
  return value;
}

const sourceSymbolsPerFile = boundedEnvironmentInteger(
  'TOOLIP_BENCHMARK_SYMBOLS_PER_FILE',
  1,
  1,
  100
);
const sourceBytesPerFile = boundedEnvironmentInteger(
  'TOOLIP_BENCHMARK_SOURCE_BYTES',
  Buffer.byteLength(defaultSourceBody),
  Buffer.byteLength('export const x=0;\n'),
  4_096
);
const seededFindingCount = boundedEnvironmentInteger(
  'TOOLIP_BENCHMARK_SEEDED_FINDINGS',
  0,
  0,
  50_000
);
const benchmarkRuleCount = boundedEnvironmentInteger(
  'TOOLIP_BENCHMARK_RULES',
  1,
  0,
  8
);
const benchmarkConcurrency = boundedEnvironmentInteger(
  'TOOLIP_BENCHMARK_CONCURRENT_SCANS',
  2,
  1,
  4
);
const graphFanout = boundedEnvironmentInteger(
  'TOOLIP_BENCHMARK_GRAPH_FANOUT',
  2,
  1,
  8
);
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
  let gcCount = 0;
  let gcDurationMs = 0;
  const gcObserver = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      gcCount += 1;
      gcDurationMs += entry.duration;
    }
  });
  gcObserver.observe({ entryTypes: ['gc'] });
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
    await new Promise<void>((resolve) => setImmediate(resolve));
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
      gcCount,
      gcDurationMs: Math.round(gcDurationMs * 100) / 100,
      result
    };
  } finally {
    gcObserver.disconnect();
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
      architecture: process.arch,
      osRelease: os.release(),
      cpuModel: os.cpus()[0]?.model ?? 'unknown',
      logicalCpuCount: os.availableParallelism(),
      hostMemoryBytes: os.totalmem(),
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

const seededRuleIds = [
  'TLP-AST-001',
  'TLP-AST-002',
  'TLP-AST-003',
  'TLP-AST-004',
  'TLP-AST-005',
  'TLP-AST-006',
  'TLP-AST-007',
  'TLP-AST-008'
] as const;
const seededRuleSource = [
  "eval('benchmark-seed');\n",
  "new Function('return 1');\n",
  "seededExec('benchmark-seed');\n",
  "seededExecSync('benchmark-seed');\n",
  'db.query(req.query.value);\n',
  'fetch(req.query.url);\n',
  'element.innerHTML = req.query.html;\n',
  'Object.assign(target, req.body);\n'
].slice(0, benchmarkRuleCount);
const sourceDeclarations = Array.from(
  { length: sourceSymbolsPerFile },
  (_, symbol) => `export const fixtureValue${symbol} = ${symbol};\n`
).join('');
const childProcessImports =
  benchmarkRuleCount >= 3
    ? "import { exec as seededExec, execSync as seededExecSync } from 'node:child_process';\n"
    : '';
const sourceContentCache = new Map<string, string>();

function sourceFileContent(index: number, incremental = false): string {
  const seeded = index < seededFindingCount;
  const cacheKey = `${seeded}:${incremental ? index : ''}`;
  const cached = sourceContentCache.get(cacheKey);
  if (cached) return cached;
  const ruleLines = seeded ? seededRuleSource.join('') : '';
  const imports = seeded && benchmarkRuleCount >= 3 ? childProcessImports : '';
  const changed = incremental ? `// incremental revision ${index}\n` : '';
  const prefix = `${sourceDeclarations}${imports}${ruleLines}${changed}`;
  if (Buffer.byteLength(prefix) > 4_096) {
    throw new Error(
      'benchmark source dimensions exceed the 4,096-byte per-file scanner limit'
    );
  }
  const prefixBytes = Buffer.byteLength(prefix);
  const paddingBytes = sourceBytesPerFile - prefixBytes;
  const content =
    paddingBytes <= 0
      ? prefix
      : paddingBytes < 3
        ? `${prefix}${' '.repeat(paddingBytes)}`
        : `${prefix}//${'x'.repeat(paddingBytes - 3)}\n`;
  if (Buffer.byteLength(content) > 4_096) {
    throw new Error(
      'benchmark source dimensions exceed the 4,096-byte per-file scanner limit'
    );
  }
  sourceContentCache.set(cacheKey, content);
  return content;
}

function sourceFixtureSha256(
  size: number,
  extraFiles: readonly { path: string; content: string }[] = [],
  changedFile?: { index: number; content: string }
): string {
  const hash = createHash('sha256');
  const update = (filePath: string, content: string): void => {
    hash.update(filePath).update('\0').update(content).update('\0');
  };
  for (let index = 0; index < size; index += 1) {
    const name = `source-${index.toString().padStart(6, '0')}.ts`;
    update(
      name,
      changedFile?.index === index
        ? changedFile.content
        : sourceFileContent(index)
    );
  }
  for (const file of [...extraFiles].sort((left, right) =>
    left.path.localeCompare(right.path)
  ))
    update(file.path, file.content);
  return hash.digest('hex');
}

function sourceFixtureBytes(size: number): number {
  const seeded = Math.min(seededFindingCount, size);
  const seededBytes = Buffer.byteLength(sourceFileContent(0));
  const ordinaryBytes =
    seeded < size ? Buffer.byteLength(sourceFileContent(seeded)) : 0;
  return seeded * seededBytes + (size - seeded) * ordinaryBytes;
}

function countSeededRuleFindings(
  findings: readonly { ruleId: string }[]
): Record<string, number> {
  const seededIds = new Set<string>(seededRuleIds.slice(0, benchmarkRuleCount));
  const counts: Record<string, number> = {};
  for (const ruleId of seededIds) counts[ruleId] = 0;
  for (const finding of findings) {
    if (seededIds.has(finding.ruleId))
      counts[finding.ruleId] = (counts[finding.ruleId] ?? 0) + 1;
  }
  return counts;
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
        for (let offset = 1; offset <= graphFanout; offset += 1) {
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
    const lockfileText = JSON.stringify(lockfile);
    await writeFile(path.join(root, 'package-lock.json'), lockfileText);

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
        fixtureSha256: createHash('sha256').update(lockfileText).digest('hex'),
        graphFanout: shape === 'wide' ? 0 : graphFanout,
        filesOpened: 1,
        graphEdges:
          shape === 'wide'
            ? size
            : size <= graphFanout
              ? (size * (size - 1)) / 2
              : (size - graphFanout) * graphFanout +
                (graphFanout * (graphFanout - 1)) / 2
      });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function createSourceFixture(root: string, size: number): Promise<void> {
  const batchSize = 128;
  for (let offset = 0; offset < size; offset += batchSize) {
    const end = Math.min(size, offset + batchSize);
    await Promise.all(
      Array.from({ length: end - offset }, (_, relative) => {
        const index = offset + relative;
        const name = `source-${index.toString().padStart(6, '0')}.ts`;
        return writeFile(path.join(root, name), sourceFileContent(index));
      })
    );
  }
}

async function readFixture(
  root: string,
  files: Awaited<ReturnType<typeof walkProjectFiles>>
) {
  const bodyBytes = Math.max(
    ...Array.from({ length: Math.min(files.length, 32) }, (_, index) =>
      Buffer.byteLength(sourceFileContent(index))
    )
  );
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
        fixtureSha256: sourceFixtureSha256(size),
        sourceSymbolsPerFile,
        sourceRuleCount: benchmarkRuleCount,
        sourceBytesPerFile: Buffer.byteLength(sourceFileContent(0)),
        sourceBytesTarget: sourceBytesPerFile,
        sourceBytes: sourceFixtureBytes(size),
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
  const fixtureSha256 = createHash('sha256')
    .update([...directories].sort().join('\0'))
    .digest('hex');

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
    fixtureSha256,
    directoriesIndexed: indexed.result.directoryCount,
    directoryQueries: indexed.result.queryCount
  });

  if (size <= 1_000) {
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
      fixtureSha256,
      directoriesScanned: legacy.result.directoryCount,
      directoryQueries: legacy.result.queryCount,
      baselineRevision: '41a3a9319b19bfb2c2290bafd1bb9fab794ddcd0'
    });
  } else {
    emit('ast-source-directory-full-scan-reference', size, 'skipped', {
      reason: 'quadratic full-scan reference is capped at 1,000 queries',
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
    const packageJson = JSON.stringify({
      name: 'toolip-benchmark-fixture',
      version: '1.0.0'
    });
    const lockfile = JSON.stringify({
      name: 'toolip-benchmark-fixture',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': { name: 'toolip-benchmark-fixture', version: '1.0.0' }
      }
    });
    const gitignore = '.env*\n*.pem\n*.key\nnode_modules/\n';
    const extraFiles = [
      { path: 'package.json', content: packageJson },
      { path: 'package-lock.json', content: lockfile },
      { path: '.gitignore', content: gitignore }
    ];
    await writeFile(path.join(root, 'package.json'), packageJson);
    await writeFile(path.join(root, 'package-lock.json'), lockfile);
    await writeFile(path.join(root, '.gitignore'), gitignore);
    await runGitChecked(['init'], { cwd: root });
    await runGitChecked(['add', '-A'], { cwd: root });
    for (const pass of passes) {
      const changedSource = sourceFileContent(0, true);
      if (pass === 'incremental')
        await writeFile(path.join(root, 'source-000000.ts'), changedSource);
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
            `full repository scan was incomplete at ${size} source files: ${JSON.stringify({ analysis: scorecard.analysis, warnings: scorecard.warnings, cache: analysisCache ? { entries: analysisCache.size, bytes: analysisCache.byteSize } : undefined })}`
          );
        }
        const expectedSeeded = Math.min(seededFindingCount, size);
        const detectedByRule = countSeededRuleFindings(scorecard.findings);
        const expectedByRule = Object.fromEntries(
          seededRuleIds
            .slice(0, benchmarkRuleCount)
            .map((ruleId) => [ruleId, expectedSeeded])
        );
        if (
          Object.entries(expectedByRule).some(
            ([ruleId, count]) => detectedByRule[ruleId] !== count
          )
        )
          throw new Error(
            `seeded AST finding mismatch: expected ${JSON.stringify(expectedByRule)}, detected ${JSON.stringify(detectedByRule)}`
          );
        const detectedSeeded = Object.values(detectedByRule).reduce(
          (total, count) => total + count,
          0
        );
        previousSnapshot = snapshot;
        return {
          snapshotReads: snapshot.metrics.filesRead,
          snapshotBytesRead: snapshot.metrics.bytesRead,
          snapshotFilesReused: snapshot.metrics.filesReused,
          cacheHits: scorecard.cacheMetrics.hits,
          cacheMisses: scorecard.cacheMetrics.misses,
          astProjectCacheHits: scorecard.cacheMetrics.astProjectHits,
          astProjectCacheMisses: scorecard.cacheMetrics.astProjectMisses,
          resultCache: scorecard.cacheMetrics.resultCache,
          seededFindingsExpected: expectedSeeded * benchmarkRuleCount,
          seededFindingsDetected: detectedSeeded,
          seededFindingsByRule: detectedByRule,
          seededFindingFiles: expectedSeeded,
          findings: scorecard.findings.length,
          filesDiscovered: context.summary.totalFiles,
          scorecardState: scorecard.analysis.state,
          coverage: scorecard.coverage
        };
      });
      emit(fixtureName, size, pass, {
        ...measurement,
        result: measurement.result,
        fixtureSha256: sourceFixtureSha256(
          size,
          extraFiles,
          pass === 'incremental'
            ? { index: 0, content: changedSource }
            : undefined
        ),
        sourceBytesTarget: sourceBytesPerFile,
        sourceSymbolsPerFile,
        sourceBytesPerFile: Math.max(
          Buffer.byteLength(sourceFileContent(0)),
          Buffer.byteLength(
            sourceFileContent(Math.min(seededFindingCount, size))
          )
        ),
        sourceBytes: sourceFixtureBytes(size),
        seededFindingCount: Math.min(seededFindingCount, size),
        seededFindingFiles: Math.min(seededFindingCount, size),
        sourceRuleCount: benchmarkRuleCount,
        seededRuleIds: seededRuleIds.slice(0, benchmarkRuleCount),
        timeToFirstFindingMs: null,
        timeToFirstFindingUnavailableReason:
          'scorecard returns aggregate findings after analyzer completion',
        filesOpened: measurement.result.snapshotReads,
        bytesRead: measurement.result.snapshotBytesRead,
        cacheHits: measurement.result.cacheHits,
        cacheMisses: measurement.result.cacheMisses,
        astProjectCacheHits: measurement.result.astProjectCacheHits,
        astProjectCacheMisses: measurement.result.astProjectCacheMisses,
        resultCache: measurement.result.resultCache
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
    const packageJson = JSON.stringify({
      name: 'toolip-concurrent-benchmark-fixture',
      version: '1.0.0'
    });
    const lockfile = JSON.stringify({
      name: 'toolip-concurrent-benchmark-fixture',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': { name: 'toolip-concurrent-benchmark-fixture', version: '1.0.0' }
      }
    });
    const gitignore = '.env*\n*.pem\n*.key\nnode_modules/\n';
    const extraFiles = [
      { path: 'package.json', content: packageJson },
      { path: 'package-lock.json', content: lockfile },
      { path: '.gitignore', content: gitignore }
    ];
    await writeFile(path.join(root, 'package.json'), packageJson);
    await writeFile(path.join(root, 'package-lock.json'), lockfile);
    await writeFile(path.join(root, '.gitignore'), gitignore);
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
        Array.from({ length: benchmarkConcurrency }, () =>
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
      const expectedSeeded = Math.min(seededFindingCount, size);
      if (
        results.some(
          (scorecard) =>
            scorecard.analysis.state !== 'complete' ||
            scorecard.coverage.state !== 'complete' ||
            scorecard.coverage.scanned !== expectedFiles ||
            Object.entries(countSeededRuleFindings(scorecard.findings)).some(
              ([, count]) => count !== expectedSeeded
            )
        )
      )
        throw new Error(`concurrent scorecard was incomplete at ${size} files`);
      return results.map((scorecard) => ({
        findings: scorecard.findings.length,
        seededFindingsExpected: expectedSeeded * benchmarkRuleCount,
        seededFindingsDetected: Object.values(
          countSeededRuleFindings(scorecard.findings)
        ).reduce((total, count) => total + count, 0),
        seededFindingsByRule: countSeededRuleFindings(scorecard.findings),
        seededFindingFiles: expectedSeeded,
        analysis: scorecard.analysis.state,
        coverage: scorecard.coverage.state,
        scanned: scorecard.coverage.scanned,
        astProjectCacheMisses: scorecard.cacheMetrics.astProjectMisses,
        resultCache: scorecard.cacheMetrics.resultCache
      }));
    });
    emit('repository-security-scorecard-concurrent-pair', size, 'cold', {
      ...measurement,
      result: measurement.result,
      fixtureSha256: sourceFixtureSha256(size, extraFiles),
      sourceSymbolsPerFile,
      sourceBytesPerFile: Math.max(
        Buffer.byteLength(sourceFileContent(0)),
        Buffer.byteLength(sourceFileContent(Math.min(seededFindingCount, size)))
      ),
      sourceBytesTarget: sourceBytesPerFile,
      sourceBytes: sourceFixtureBytes(size),
      seededFindingCount: Math.min(seededFindingCount, size),
      seededFindingFiles: Math.min(seededFindingCount, size),
      sourceRuleCount: benchmarkRuleCount,
      seededRuleIds: seededRuleIds.slice(0, benchmarkRuleCount),
      timeToFirstFindingMs: null,
      timeToFirstFindingUnavailableReason:
        'scorecard returns aggregate findings after analyzer completion',
      concurrentScans: benchmarkConcurrency,
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
    fixtureSha256: createHash('sha256').update(content).digest('hex'),
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
      fixtureSha256: createHash('sha256').update(content).digest('hex'),
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
