import path from 'node:path';
import { realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import type { AnalysisResultCache } from '../application/task-scheduler.js';
import {
  analyzeAstProjectInWorker,
  planAstProjectInWorker
} from '../analyzers/ast/project-analysis-worker-client.js';
import type { AstProjectInput } from '../analyzers/ast/source-analysis.js';
import { InfrastructureAnalyzer } from '../analyzers/iac/analyzer.js';
import { DockerfileAnalyzer } from '../analyzers/docker/analyzer.js';
import {
  scanMaliciousContent,
  shouldInspectMaliciousContent
} from '../analyzers/malicious-content/analyzer.js';
import { type AnalysisCoverage, coverageOf } from '../contracts/analysis.js';
import type { Finding } from '../contracts/finding.js';
import {
  createScannerContext,
  type ScannerContext
} from './scanner-context.js';
import {
  createProjectSnapshot,
  isScannerContextFromSnapshot,
  scannerContextFromSnapshot,
  snapshotContentProvider,
  type ProjectSnapshot
} from '../application/project-snapshot.js';
import {
  TextFileReader,
  type TextFileBudget,
  type TextFileReadResult
} from './text-file-reader.js';
import { bindSourceProvenance } from './source-provenance.js';
import {
  runWasmAnalyzerPlugin,
  type WasmAnalyzerPlugin
} from './analyzer-plugin.js';
import {
  configSecurityPatterns,
  secretPatterns,
  securityHeaderNames,
  type SecurityPattern
} from './security-patterns.js';
import {
  analyzeRulePacks,
  assertRulePackScanLimits,
  rulePackFindingBudget,
  type VerifiedRulePack
} from './rule-packs.js';
import {
  findSecretMatches,
  createLineLocator,
  isTestFile,
  secretEvidence,
  secretFingerprint,
  createFixtureSuppressionIndex,
  trustedSuppressionFor,
  type TrustedFixtureSuppression
} from './secret-utils.js';

export type SecurityDoctorResult = {
  findings: Finding[];
  /** Canonical completeness: skipped or unreadable eligible files make a run partial. */
  coverage: AnalysisCoverage;
  warnings?: string[];
  suppressedFixtures: { count: number; ids: string[] };
  summary: {
    filesDiscovered: number;
    filesEligible: number;
    filesScanned: number;
    filesSkipped: number;
    readFailures: number;
    bytesScanned: number;
    secrets: number;
    dangerousCode: number;
    maliciousContent: number;
    configuration: number;
    headers: number;
  };
  maliciousContent: {
    coverage: AnalysisCoverage;
    filesScanned: number;
    bytesScanned: number;
  };
  infrastructure: { coverage: AnalysisCoverage; findings: number };
  docker: { coverage: AnalysisCoverage; findings: number; files: number };
  cacheMetrics: {
    hits: number;
    misses: number;
    astProjectHits: number;
    astProjectMisses: number;
    resultCache: {
      hits: number;
      misses: number;
      evictions: number;
      entries: number;
      retainedSerializedBytes: number;
    };
  };
  analyzerPlugins: Array<{
    id: string;
    sha256: string;
    keyId: string;
    coverage: AnalysisCoverage;
    findings: number;
  }>;
};

export type SecurityDoctorOptions = {
  budget?: TextFileBudget;
  signal?: AbortSignal;
  /** Reuse exactly the immutable snapshot captured by the caller. */
  snapshot?: ProjectSnapshot;
  /** Caller-owned cache; unchanged path/content/rule inputs reuse file findings. */
  analysisCache?: AnalysisResultCache;
  /**
   * Supplies file content instead of reading the worktree. Pre-commit uses this
   * to scan the exact staged blobs, never the (possibly different) working copy.
   */
  contentProvider?: (
    file: ScannerContext['files'][number]
  ) => Promise<TextFileReadResult>;
  /** Exact index-tree files used only to resolve staged execution chains. */
  maliciousContentFiles?: readonly ScannerContext['files'][number][];
  /** Trusted caller-owned fixture policy; comments in scanned content never grant suppression. */
  trustedFixtureSuppressions?: readonly TrustedFixtureSuppression[];
  /** Optional already-verified declarative rule packs. */
  rulePacks?: readonly VerifiedRulePack[];
  /** Signed, no-import WASM plugins require an explicit independent opt-in. */
  analyzerPlugins?: readonly WasmAnalyzerPlugin[];
  enableExecutablePlugins?: boolean;
};

const secretScanExtensions = new Set([
  'js',
  'jsx',
  'ts',
  'tsx',
  'mjs',
  'cjs',
  'json',
  'yml',
  'yaml',
  'env',
  'txt',
  'pem',
  'key'
]);

const codeExtensions = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs']);
const astProjectCacheChunkSize = 16;
const astProjectCacheVersion = 'security-doctor-ast-project-v2';

type AstProjectCacheChunk = {
  taskId: string;
  paths: string[];
};

type AstProjectCacheValue = {
  paths: string[];
  fingerprints: Array<[string, string]>;
  findings: Array<[string, Finding[]]>;
  dependencyDigests: Array<[string, string]>;
};

function createAstProjectCacheChunks(
  sortedFilePaths: readonly string[]
): AstProjectCacheChunk[] {
  const chunks: AstProjectCacheChunk[] = [];
  for (
    let offset = 0;
    offset < sortedFilePaths.length;
    offset += astProjectCacheChunkSize
  ) {
    const paths = sortedFilePaths.slice(
      offset,
      offset + astProjectCacheChunkSize
    );
    chunks.push({
      taskId: createHash('sha256')
        .update('ast-project-cache-paths-v2\0')
        .update(JSON.stringify(paths))
        .digest('hex'),
      paths
    });
  }
  return chunks;
}

function createAstProjectFingerprints(
  inputs: readonly AstProjectInput[],
  componentDigests: ReadonlyMap<string, string>,
  dependencyDigests: ReadonlyMap<string, string>
): Map<string, string> {
  const fingerprints = new Map<string, string>();
  for (const input of inputs) {
    const componentDigest = componentDigests.get(input.filePath);
    const dependencyDigest = dependencyDigests.get(input.filePath);
    if (!componentDigest || !dependencyDigest)
      throw new Error('AST component plan omitted an input digest');
    fingerprints.set(
      input.filePath,
      createHash('sha256')
        .update('ast-project-file-cache-v2\0')
        .update(input.filePath)
        .update('\0')
        .update(createHash('sha256').update(input.content).digest('hex'))
        .update('\0')
        .update(componentDigest)
        .update('\0')
        .update(dependencyDigest)
        .digest('hex')
    );
  }
  return fingerprints;
}

function astAnalysisFailureKind(error: unknown): string {
  if (!(error instanceof Error)) return 'unknown failure';
  if (error.name === 'TimeoutError') return 'worker timed out';
  if (error.name === 'AbortError') return 'worker cancelled';
  if (error.name === 'CapacityError') return 'worker capacity exhausted';
  if (
    /worker exited before (?:analysis|planning) \(code \d+\)/u.test(
      error.message
    )
  )
    return 'worker exited before returning a result';
  if (/input budget exceeded/u.test(error.message))
    return 'input budget exceeded';
  if (/invalid component plan/u.test(error.message))
    return 'worker returned an invalid component plan';
  if (/inconsistent component data/u.test(error.message))
    return 'worker returned inconsistent component or dependency digests';
  if (/omitted an input digest/u.test(error.message))
    return 'worker omitted a required component fingerprint';
  if (/omitted files from its result/u.test(error.message))
    return 'worker omitted one or more analyzed files';
  if (/returned an invalid result/u.test(error.message))
    return 'worker returned an invalid analysis result';
  if (/dependency digest mismatch/u.test(error.message))
    return 'worker dependency digests disagreed with the component plan';
  if (/missing finding/u.test(error.message))
    return 'worker omitted a file finding';
  if (
    /returned (?:an )?(?:invalid|inconsistent)|omitted files|disagrees with/u.test(
      error.message
    )
  )
    return 'worker result validation failed';
  const code = (error as Error & { code?: unknown }).code;
  if (typeof code === 'string' && /^ERR_[A-Z0-9_]{1,64}$/u.test(code))
    return `worker error ${code}`;
  return `worker failure (${error.name.replace(/[^A-Za-z0-9]/gu, '').slice(0, 40) || 'Error'})`;
}

function readAstProjectCache(
  cache: AnalysisResultCache | undefined,
  scope: string,
  chunks: readonly AstProjectCacheChunk[],
  fingerprints: ReadonlyMap<string, string>,
  expectedDependencyDigests: ReadonlyMap<string, string>
): {
  findingsByPath: Map<string, readonly Finding[]>;
  uncachedPaths: Set<string>;
} {
  const findingsByPath = new Map<string, readonly Finding[]>();
  const uncachedPaths = new Set<string>();
  for (const chunk of chunks) {
    const value = cache?.get<AstProjectCacheValue>(
      scope,
      chunk.taskId,
      astProjectCacheVersion
    );
    if (
      !value ||
      !Array.isArray(value.paths) ||
      value.paths.length !== chunk.paths.length ||
      value.paths.some((filePath, index) => filePath !== chunk.paths[index]) ||
      !Array.isArray(value.fingerprints) ||
      value.fingerprints.length !== chunk.paths.length ||
      value.fingerprints.some(
        (entry, index) =>
          !Array.isArray(entry) ||
          entry.length !== 2 ||
          entry[0] !== chunk.paths[index] ||
          typeof entry[1] !== 'string' ||
          !/^[a-f0-9]{64}$/u.test(entry[1])
      ) ||
      !Array.isArray(value.findings) ||
      !Array.isArray(value.dependencyDigests) ||
      value.findings.length !== chunk.paths.length ||
      value.dependencyDigests.length !== chunk.paths.length ||
      value.findings.some(
        (entry, index) =>
          !Array.isArray(entry) ||
          entry[0] !== chunk.paths[index] ||
          !Array.isArray(entry[1])
      ) ||
      value.dependencyDigests.some(
        (entry, index) =>
          !Array.isArray(entry) ||
          entry.length !== 2 ||
          entry[0] !== chunk.paths[index] ||
          typeof entry[1] !== 'string' ||
          !/^[a-f0-9]{64}$/u.test(entry[1])
      ) ||
      new Set(value.dependencyDigests.map(([filePath]) => filePath)).size !==
        chunk.paths.length ||
      new Set(value.findings.map(([filePath]) => filePath)).size !==
        chunk.paths.length ||
      new Set(value.fingerprints.map(([filePath]) => filePath)).size !==
        chunk.paths.length
    ) {
      for (const filePath of chunk.paths) uncachedPaths.add(filePath);
      continue;
    }
    for (let index = 0; index < chunk.paths.length; index += 1) {
      const filePath = chunk.paths[index];
      const fingerprint = value.fingerprints[index]?.[1];
      const dependencyDigest = value.dependencyDigests[index]?.[1];
      const expectedDigest = expectedDependencyDigests.get(filePath);
      if (
        !filePath ||
        fingerprint !== fingerprints.get(filePath) ||
        !expectedDigest ||
        dependencyDigest !== expectedDigest
      ) {
        if (filePath) uncachedPaths.add(filePath);
        continue;
      }
      const findingEntry = value.findings[index];
      if (findingEntry) findingsByPath.set(filePath, findingEntry[1]);
    }
  }
  return { findingsByPath, uncachedPaths };
}

/** Runs the local security checks and records truthful scan coverage. */
export async function runSecurityDoctor(
  rootOrContext: string | ScannerContext,
  options: SecurityDoctorOptions = {}
): Promise<SecurityDoctorResult> {
  const resultCacheBefore = options.analysisCache?.metrics ?? {
    hits: 0,
    misses: 0,
    evictions: 0,
    entries: 0,
    retainedSerializedBytes: 0
  };
  const suppliedContext =
    typeof rootOrContext === 'string' ? undefined : rootOrContext;
  let snapshot = options.snapshot;
  const captureSuppliedContext =
    !suppliedContext || (!options.contentProvider && !options.signal);
  if (!snapshot && captureSuppliedContext) {
    try {
      snapshot = await createProjectSnapshot(
        suppliedContext?.root ?? (rootOrContext as string),
        {
          signal: options.signal,
          maxFiles: options.budget?.maxFiles,
          maxFileBytes: options.budget?.maxFileBytes,
          maxTotalBytes: options.budget?.maxTotalBytes,
          ...(suppliedContext ? { discoveredFiles: suppliedContext.files } : {})
        }
      );
    } catch (error) {
      // Preserve the established incomplete-scan behavior when a caller
      // supplies a context whose files changed after discovery. The ordinary
      // bounded readers below will report those files as skipped; AST analysis
      // remains unavailable rather than reading a different source revision.
      if (
        !suppliedContext ||
        !(error instanceof Error) ||
        !error.message.startsWith('snapshot incomplete for ')
      )
        throw error;
    }
  }
  const context = snapshot
    ? typeof rootOrContext !== 'string' &&
      isScannerContextFromSnapshot(rootOrContext, snapshot)
      ? rootOrContext
      : await scannerContextFromSnapshot(snapshot)
    : typeof rootOrContext === 'string'
      ? await createScannerContext(rootOrContext)
      : rootOrContext;
  if (
    snapshot &&
    (await realpath(
      path.resolve(
        typeof rootOrContext === 'string' ? rootOrContext : rootOrContext.root
      )
    ).catch(() => undefined)) !== snapshot.root
  ) {
    throw new Error('project snapshot root does not match the scan root');
  }
  const contentProvider =
    options.contentProvider ??
    (snapshot ? snapshotContentProvider(snapshot) : undefined);
  assertRulePackScanLimits(options.rulePacks ?? []);
  if (
    options.analyzerPlugins?.length &&
    options.enableExecutablePlugins !== true
  )
    throw new Error(
      'Executable analyzer plugins require explicit operator opt-in.'
    );
  const reader = new TextFileReader(options.budget, { root: context.root });
  const findings: Finding[] = [];
  const knownContent = new Map<string, string>();
  const knownBinaryPaths = new Set(
    snapshot?.files.filter((file) => file.binary).map((file) => file.path) ?? []
  );
  const warnings: string[] = [];
  let astFindingsByPath: ReadonlyMap<string, readonly Finding[]> | undefined;
  let astDependencyDigests: ReadonlyMap<string, string> | undefined;
  let astAnalysisIncomplete = false;
  let astAnalysisFailure: string | undefined;
  let astProjectDigest: string | undefined;
  let astProjectCacheHits = 0;
  let astProjectCacheMisses = 0;
  let pendingAstProjectCache:
    | {
        scope: string;
        chunks: AstProjectCacheChunk[];
        fingerprints: ReadonlyMap<string, string>;
        findingsByPath: ReadonlyMap<string, readonly Finding[]>;
        dependencyDigests: ReadonlyMap<string, string>;
      }
    | undefined;
  if (snapshot) {
    const astFiles = snapshot.files
      .filter(
        (file) =>
          codeExtensions.has(path.extname(file.path).slice(1).toLowerCase()) &&
          !file.path.endsWith('.d.ts') &&
          !file.path.endsWith('.map') &&
          !file.path.startsWith('dist/')
      )
      .sort((left, right) => left.path.localeCompare(right.path));
    const astInputs = astFiles.flatMap((file) =>
      !file.binary && file.content !== undefined
        ? [
            {
              filePath: file.path,
              absolutePath: path.resolve(context.root, file.path),
              content: file.content
            }
          ]
        : []
    );
    const projectHash = createHash('sha256').update('ast-project-input-v1\0');
    for (const file of astFiles)
      projectHash
        .update(file.path)
        .update('\0')
        .update(file.sha256)
        .update('\0');
    astProjectDigest = projectHash.digest('hex');
    astAnalysisIncomplete = astInputs.length !== astFiles.length;
    if (!astAnalysisIncomplete && astInputs.length > 0) {
      try {
        if (!options.analysisCache) {
          astProjectCacheMisses = Math.ceil(
            astInputs.length / astProjectCacheChunkSize
          );
          const analyzed = await analyzeAstProjectInWorker(astInputs, {
            signal: options.signal
          });
          astFindingsByPath = analyzed.findingsByPath;
          astDependencyDigests = analyzed.dependencyDigests;
        } else {
          const astCacheScope = `ast-project:${context.root}`;
          const astCacheChunks = createAstProjectCacheChunks(
            astInputs.map((input) => input.filePath)
          );
          const cacheIsEmpty = astCacheChunks.every(
            (chunk) =>
              !options.analysisCache?.has(
                astCacheScope,
                chunk.taskId,
                astProjectCacheVersion
              )
          );
          if (cacheIsEmpty) {
            // A first scan has no previous component data to compare. Let the
            // analysis worker compute findings and component digests together
            // instead of cloning the full source tree into a plan worker and
            // then transferring it again for analysis.
            const analyzed = await analyzeAstProjectInWorker(astInputs, {
              signal: options.signal
            });
            const fingerprints = createAstProjectFingerprints(
              astInputs,
              analyzed.componentDigests,
              analyzed.dependencyDigests
            );
            astFindingsByPath = analyzed.findingsByPath;
            astDependencyDigests = analyzed.dependencyDigests;
            astProjectCacheMisses = astCacheChunks.length;
            pendingAstProjectCache = {
              scope: astCacheScope,
              chunks: astCacheChunks,
              fingerprints,
              findingsByPath: analyzed.findingsByPath,
              dependencyDigests: analyzed.dependencyDigests
            };
          } else {
            const plan = await planAstProjectInWorker(astInputs, {
              signal: options.signal
            });
            const fingerprints = createAstProjectFingerprints(
              astInputs,
              plan.componentDigests,
              plan.dependencyDigests
            );
            const cachedAst = readAstProjectCache(
              options.analysisCache,
              astCacheScope,
              astCacheChunks,
              fingerprints,
              plan.dependencyDigests
            );
            const componentDigestsToAnalyze = new Set<string>();
            for (const filePath of cachedAst.uncachedPaths) {
              const digest = plan.componentDigests.get(filePath);
              if (digest) componentDigestsToAnalyze.add(digest);
            }
            const pathsToAnalyze = new Set<string>();
            for (const [filePath, digest] of plan.componentDigests)
              if (componentDigestsToAnalyze.has(digest))
                pathsToAnalyze.add(filePath);

            // readAstProjectCache owns this materialized map, so invalidation
            // can delete stale paths in place without a second O(F) map copy.
            const cachedFindingsByPath = cachedAst.findingsByPath;
            for (const filePath of pathsToAnalyze)
              cachedFindingsByPath.delete(filePath);
            astDependencyDigests = plan.dependencyDigests;
            astProjectCacheHits = astCacheChunks.filter((chunk) =>
              chunk.paths.every((filePath) => !pathsToAnalyze.has(filePath))
            ).length;
            astProjectCacheMisses = astCacheChunks.length - astProjectCacheHits;
            if (pathsToAnalyze.size === 0) {
              astFindingsByPath = cachedFindingsByPath;
            } else {
              const analysisInputs = astInputs.filter((input) =>
                pathsToAnalyze.has(input.filePath)
              );
              const analyzed = await analyzeAstProjectInWorker(analysisInputs, {
                signal: options.signal
              });
              for (const input of analysisInputs) {
                if (
                  !analyzed.findingsByPath.has(input.filePath) ||
                  analyzed.dependencyDigests.get(input.filePath) !==
                    plan.dependencyDigests.get(input.filePath)
                )
                  throw new Error(
                    'AST worker output disagrees with its component plan (missing finding or dependency digest mismatch)'
                  );
              }
              astFindingsByPath = new Map([
                ...cachedFindingsByPath,
                ...analyzed.findingsByPath
              ]);
              pendingAstProjectCache = {
                scope: astCacheScope,
                chunks: astCacheChunks.filter((chunk) =>
                  chunk.paths.some((filePath) => pathsToAnalyze.has(filePath))
                ),
                fingerprints,
                findingsByPath: astFindingsByPath,
                dependencyDigests: plan.dependencyDigests
              };
            }
          }
        }
      } catch (error) {
        astFindingsByPath = undefined;
        astDependencyDigests = undefined;
        astAnalysisIncomplete = true;
        astAnalysisFailure = astAnalysisFailureKind(error);
      }
    }
    if (astAnalysisIncomplete)
      warnings.push(
        `cross-file TypeScript taint analysis is incomplete for this project snapshot (${astAnalysisFailure ?? 'unknown failure'})`
      );
  }
  let filesEligible = 0;
  let filesScanned = 0;
  let filesSkipped = 0;
  let readFailures = 0;
  let providerBytes = 0;
  const suppressedFixtureIds: string[] = [];
  let rulePackFindings = 0;
  let rulePackCoverageIncomplete = false;
  const fixturePolicy = createFixtureSuppressionIndex(
    options.trustedFixtureSuppressions
  );
  const cacheScope = createHash('sha256')
    .update(
      JSON.stringify({
        root: context.root,
        // Rules and trusted configuration are inputs too. The per-file
        // content key below keeps unrelated source edits incremental, while
        // a policy/rule configuration change invalidates prior conclusions.
        configDigest: options.snapshot?.configDigest ?? null,
        analyzerVersion: 'security-doctor-source-v2',
        fixtureSuppressions: [...(options.trustedFixtureSuppressions ?? [])]
          .map((item) => ({
            id: item.id,
            ruleId: item.ruleId,
            filePath: item.filePath,
            owner: item.owner,
            justification: item.justification,
            expiresAt: item.expiresAt
          }))
          .sort((left, right) => left.id.localeCompare(right.id)),
        rulePacks: [...(options.rulePacks ?? [])]
          .map((pack) => ({
            sha256: pack.sha256,
            trust: pack.trust,
            keyId: pack.keyId
          }))
          .sort((left, right) => left.sha256.localeCompare(right.sha256))
      })
    )
    .digest('hex');
  let cacheHits = 0;
  let cacheMisses = 0;

  const eligibleFiles = context.files.filter((file) =>
    shouldScanSecrets(file.relativePath, file.extension)
  );
  filesEligible = eligibleFiles.length;
  let cancelled = false;

  for (const [index, file] of eligibleFiles.entries()) {
    const read = contentProvider
      ? await contentProvider(file)
      : await reader.read(file.absolutePath, options.signal, file.snapshot);
    if (contentProvider && read.status === 'ok') {
      providerBytes += read.bytes;
    }

    if (read.status !== 'ok') {
      if (
        read.status === 'binary' &&
        !isCredentialNamedFile(file.relativePath) &&
        !secretScanExtensions.has(file.extension)
      ) {
        filesEligible -= 1;
        continue;
      }
      filesSkipped += 1;
      if (read.status === 'failed') {
        readFailures += 1;
        warnings.push(`${file.relativePath}: ${read.error}`);
      } else {
        warnings.push(`${file.relativePath}: skipped (${read.status})`);
      }

      if (read.status === 'cancelled') {
        // Files after the cancellation point were never examined: count them
        // so the run cannot look complete.
        cancelled = true;
        filesSkipped += eligibleFiles.length - index - 1;
        break;
      }
      continue;
    }

    filesScanned += 1;
    knownContent.set(file.relativePath, read.content);
    const sourceDependencyDigest = codeExtensions.has(file.extension)
      ? (astDependencyDigests?.get(file.relativePath) ??
        astProjectDigest ??
        'ast-project-unavailable')
      : '';
    const taskId = createHash('sha256')
      .update(
        `${file.relativePath}\0${read.sha256 ?? read.content}\0${sourceDependencyDigest}`
      )
      .digest('hex');
    let cachedAnalysis = options.analysisCache?.get<{
      findings: Finding[];
      suppressedFixtureIds: string[];
    }>(cacheScope, taskId, 'security-doctor-source-v3');
    if (cachedAnalysis) {
      cacheHits++;
      suppressedFixtureIds.push(...cachedAnalysis.suppressedFixtureIds);
      const customFindings = cachedAnalysis.findings.filter((finding) =>
        finding.source.startsWith('signed-rule-pack:')
      );
      const remaining = Math.max(0, rulePackFindingBudget - rulePackFindings);
      if (customFindings.length > remaining) {
        cachedAnalysis = {
          ...cachedAnalysis,
          findings: [
            ...cachedAnalysis.findings.filter(
              (finding) => !finding.source.startsWith('signed-rule-pack:')
            ),
            ...customFindings.slice(0, remaining)
          ]
        };
        rulePackFindings = rulePackFindingBudget;
        rulePackCoverageIncomplete = true;
      } else {
        rulePackFindings += customFindings.length;
      }
      if (rulePackFindings >= rulePackFindingBudget) {
        rulePackCoverageIncomplete = true;
        warnings.push('declarative rule-pack output budget exhausted');
      }
    } else {
      cacheMisses++;
      const suppressedForFile: string[] = [];
      const fileFindings = scanSecretContent(file.relativePath, read.content);
      const filteredFindings = fileFindings.filter((finding) => {
        const policy = trustedSuppressionFor(
          fixturePolicy,
          finding.ruleId,
          file.relativePath
        );
        if (!policy) return true;
        suppressedForFile.push(policy.id);
        return false;
      });

      if (codeExtensions.has(file.extension)) {
        filteredFindings.push(
          ...(astFindingsByPath?.get(file.relativePath) ?? []),
          ...scanConfigurationContent(file.relativePath, read.content)
        );
      }
      if (!rulePackCoverageIncomplete && options.rulePacks?.length) {
        const customFindings = analyzeRulePacks(
          options.rulePacks,
          file.relativePath,
          read.content,
          rulePackFindingBudget - rulePackFindings
        );
        filteredFindings.push(...customFindings);
        rulePackFindings += customFindings.length;
        if (rulePackFindings >= rulePackFindingBudget) {
          rulePackCoverageIncomplete = true;
          warnings.push('declarative rule-pack output budget exhausted');
        }
      }
      cachedAnalysis = {
        findings: filteredFindings,
        suppressedFixtureIds: suppressedForFile
      };
      options.analysisCache?.set(
        cacheScope,
        taskId,
        'security-doctor-source-v3',
        cachedAnalysis
      );
      suppressedFixtureIds.push(...suppressedForFile);
    }
    findings.push(...bindSourceProvenance(cachedAnalysis.findings, file, read));
  }

  if (pendingAstProjectCache && options.analysisCache) {
    for (const chunk of pendingAstProjectCache.chunks) {
      const fingerprints = chunk.paths.flatMap(
        (filePath): Array<[string, string]> => {
          const fingerprint = pendingAstProjectCache.fingerprints.get(filePath);
          return fingerprint ? [[filePath, fingerprint]] : [];
        }
      );
      const dependencyDigests = chunk.paths.flatMap(
        (filePath): Array<[string, string]> => {
          const digest = pendingAstProjectCache.dependencyDigests.get(filePath);
          return digest ? [[filePath, digest]] : [];
        }
      );
      // Never persist a partial or placeholder record if an internal plan is
      // inconsistent. The next run will safely recompute this chunk.
      if (
        fingerprints.length !== chunk.paths.length ||
        dependencyDigests.length !== chunk.paths.length
      )
        continue;
      const value: AstProjectCacheValue = {
        paths: chunk.paths,
        fingerprints,
        findings: chunk.paths.map((filePath): [string, Finding[]] => [
          filePath,
          [...(pendingAstProjectCache.findingsByPath.get(filePath) ?? [])]
        ]),
        dependencyDigests
      };
      options.analysisCache.set(
        pendingAstProjectCache.scope,
        chunk.taskId,
        astProjectCacheVersion,
        value
      );
    }
  }

  findings.push(
    ...detectMissingSecurityHeaders(
      context.files.map((file) => file.relativePath)
    )
  );

  if (contentProvider) {
    for (const file of options.maliciousContentFiles ?? context.files) {
      if (
        knownContent.has(file.relativePath) ||
        !shouldInspectMaliciousContent(file.relativePath, file.extension)
      )
        continue;
      try {
        const read = await contentProvider(file);
        if (read.status === 'ok') {
          knownContent.set(file.relativePath, read.content);
          providerBytes += read.bytes;
        } else if (read.status === 'binary') {
          knownBinaryPaths.add(file.relativePath);
        }
      } catch {
        // Missing staged blobs remain explicitly unexamined in the malicious
        // content coverage result below; never fall back to worktree bytes.
      }
    }
  }

  let maliciousContent: SecurityDoctorResult['maliciousContent'];
  try {
    const result = await scanMaliciousContent(
      context.root,
      options.signal,
      options.maliciousContentFiles ?? context.files,
      knownContent,
      contentProvider === undefined,
      knownBinaryPaths
    );
    findings.push(...result.findings);
    maliciousContent = {
      coverage: result.coverage,
      filesScanned: result.filesScanned,
      bytesScanned: result.bytesScanned
    };
  } catch {
    warnings.push(
      'malicious-content analysis failed before complete discovery'
    );
    maliciousContent = {
      coverage: coverageOf({ eligible: 1, scanned: 0, skipped: 0, failed: 1 }),
      filesScanned: 0,
      bytesScanned: 0
    };
  }

  const infrastructure = await new InfrastructureAnalyzer().analyze({
    root: context.root,
    signal: options.signal,
    options: { scannerContext: context, contentProvider }
  });
  findings.push(...infrastructure.findings);
  const docker = await new DockerfileAnalyzer().analyze({
    root: context.root,
    signal: options.signal,
    options: {
      scannerContext: context,
      snapshot,
      contentProvider
    }
  });
  findings.push(...docker.findings);

  const pluginFiles = snapshot
    ? snapshot.files
        .filter((file) => !file.binary && file.content !== undefined)
        .map((file) => ({ path: file.path, content: file.content as string }))
    : [...knownContent].map(([filePath, content]) => ({
        path: filePath,
        content
      }));
  const analyzerPlugins: SecurityDoctorResult['analyzerPlugins'] = [];
  let pluginAnalysisIncomplete = false;
  for (const plugin of options.analyzerPlugins ?? []) {
    const result = await runWasmAnalyzerPlugin(
      plugin,
      pluginFiles,
      options.signal
    );
    findings.push(...result.findings);
    warnings.push(...result.warnings);
    analyzerPlugins.push({
      id: plugin.id,
      sha256: plugin.moduleSha256,
      keyId: plugin.keyId,
      coverage: result.coverage,
      findings: result.findings.length
    });
    if (result.coverage.state !== 'complete') pluginAnalysisIncomplete = true;
  }

  const secretCoverage = coverageOf({
    eligible: filesEligible,
    scanned: filesScanned,
    skipped: filesSkipped - readFailures,
    failed: readFailures,
    excluded: context.files.length - filesEligible,
    cancelled
  });
  const infrastructureCoverage =
    infrastructure.coverage ??
    coverageOf({ eligible: 0, scanned: 0, skipped: 0, failed: 0 });
  const dockerCoverage =
    docker.coverage ??
    coverageOf({ eligible: 0, scanned: 0, skipped: 0, failed: 0 });
  const states = [
    secretCoverage.state,
    maliciousContent.coverage.state,
    infrastructureCoverage.state,
    dockerCoverage.state,
    ...analyzerPlugins.map((plugin) => plugin.coverage.state)
  ];
  const state = states.includes('failed')
    ? 'failed'
    : states.includes('partial') ||
        rulePackCoverageIncomplete ||
        pluginAnalysisIncomplete ||
        astAnalysisIncomplete
      ? 'partial'
      : 'complete';
  const coverage: AnalysisCoverage = {
    ...secretCoverage,
    state,
    ...(state === 'complete'
      ? {}
      : {
          reason:
            [
              secretCoverage.reason,
              maliciousContent.coverage.reason,
              infrastructureCoverage.reason,
              dockerCoverage.reason,
              ...analyzerPlugins
                .filter((plugin) => plugin.coverage.reason)
                .map((plugin) => `${plugin.id}: ${plugin.coverage.reason}`),
              rulePackCoverageIncomplete
                ? 'declarative rule-pack output was truncated'
                : undefined,
              astAnalysisIncomplete
                ? 'cross-file TypeScript taint coverage was incomplete'
                : undefined
            ]
              .filter((reason): reason is string => Boolean(reason))
              .join('; ') ||
            'one or more security analysis passes were incomplete'
        })
  };

  return {
    findings,
    coverage,
    warnings: warnings.length > 0 ? warnings : undefined,
    suppressedFixtures: {
      count: suppressedFixtureIds.length,
      ids: [...new Set(suppressedFixtureIds)]
    },
    summary: {
      filesDiscovered: context.files.length,
      filesEligible,
      filesScanned,
      filesSkipped,
      readFailures,
      bytesScanned: reader.usage.bytesRead + providerBytes,
      secrets: countCategory(findings, 'secrets'),
      dangerousCode: countCategory(findings, 'dangerous-code'),
      maliciousContent: countCategory(findings, 'malicious-content'),
      configuration: countCategory(findings, 'configuration'),
      headers: countCategory(findings, 'security-headers')
    },
    maliciousContent,
    infrastructure: {
      coverage: infrastructureCoverage,
      findings: infrastructure.findings.length
    },
    docker: {
      coverage: dockerCoverage,
      findings: docker.findings.length,
      files: Number(docker.metadata?.dockerfiles ?? 0)
    },
    cacheMetrics: {
      hits: cacheHits,
      misses: cacheMisses,
      astProjectHits: astProjectCacheHits,
      astProjectMisses: astProjectCacheMisses,
      resultCache: (() => {
        const current = options.analysisCache?.metrics ?? resultCacheBefore;
        return {
          hits: current.hits - resultCacheBefore.hits,
          misses: current.misses - resultCacheBefore.misses,
          evictions: current.evictions - resultCacheBefore.evictions,
          entries: current.entries,
          retainedSerializedBytes: current.retainedSerializedBytes
        };
      })()
    },
    analyzerPlugins
  };
}

/** Counts findings belonging to one canonical finding category. */
function countCategory(findings: Finding[], category: string): number {
  return findings.filter((finding) => finding.category === category).length;
}

/** Identifies source and configuration files eligible for secret inspection. */
export function shouldScanSecrets(
  relativePath: string,
  extension: string
): boolean {
  if (relativePath.endsWith('.d.ts')) return false;
  if (relativePath.endsWith('.map')) return false;
  if (relativePath.startsWith('dist/')) return false;
  if (relativePath.endsWith('.env')) return true;
  if (relativePath.includes('.env.')) return true;
  if (isCredentialNamedFile(relativePath)) return true;
  const binaryExtensions = new Set([
    '7z',
    'a',
    'avi',
    'bin',
    'bmp',
    'class',
    'bz2',
    'dll',
    'dmg',
    'dylib',
    'exe',
    'eot',
    'gif',
    'gz',
    'ico',
    'iso',
    'jar',
    'jpeg',
    'jpg',
    'mkv',
    'mov',
    'mp3',
    'mp4',
    'o',
    'pdf',
    'png',
    'psd',
    'so',
    'sqlite',
    'tar',
    'otf',
    'ttf',
    'wasm',
    'woff',
    'woff2',
    'webp',
    'xz',
    'zip',
    'zst'
  ]);
  return (
    secretScanExtensions.has(extension) || !binaryExtensions.has(extension)
  );
}

/** Identifies credential-named files that remain in coverage even when unreadable. */
function isCredentialNamedFile(relativePath: string): boolean {
  const basename = relativePath.split('/').at(-1)?.toLowerCase() ?? '';
  return /^(\.npmrc|\.pypirc|\.netrc|\.env(?:\..*)?|credentials(?:\..*)?|secrets?(?:\..*)?)$/.test(
    basename
  );
}

/** Produces secret findings from a single already-read source file. */
export function scanSecretContent(
  relativePath: string,
  content: string
): Finding[] {
  const findings: Finding[] = [];
  const testFile = isTestFile(relativePath);
  const codeFile =
    /\.(?:[cm]?[jt]sx?|vue|svelte|py|rb|go|rs|java|kt|kts|php|c|h|cc|cpp|cxx|hpp|cs|swift|scala|sh|bash|zsh)$/i.test(
      relativePath
    );

  for (const pattern of secretPatterns) {
    const regex =
      pattern.id === 'TOOLIP-SECRET-HARDCODED-PASSWORD' && codeFile
        ? /\b(password|passwd|pwd)\s*[:=]\s*(?:"(?!\$)[^"\n]{8,}"|'(?!\$)[^'\n]{8,}')/gi
        : pattern.regex;
    for (const match of findSecretMatches(content, regex)) {
      const evidence = secretEvidence(match.value);
      findings.push({
        id: `${pattern.id}:${relativePath}:${match.line}:${match.column}`,
        ruleId: pattern.id,
        title: testFile
          ? `Potential test fixture: ${pattern.title}`
          : pattern.title,
        severity: pattern.severity,
        confidence: testFile ? 'medium' : 'high',
        category: pattern.category,
        message: testFile
          ? `${pattern.message} The value is in a test file, but severity is preserved until it is explicitly identified as synthetic fixture data.`
          : pattern.message,
        source: 'security-doctor',
        remediation: { summary: pattern.recommendation },
        location: {
          file: relativePath,
          line: match.line,
          column: match.column
        },
        evidence: [evidence],
        metadata: {
          testFixtureCandidate: testFile,
          occurrenceFingerprint: match.fingerprint
        }
      });
    }
  }

  return findings;
}

/** Inspects configuration text for unsafe security settings. */
export function scanConfigurationContent(
  relativePath: string,
  content: string
): Finding[] {
  const findings: Finding[] = [];
  const locate = createLineLocator(content);

  for (const pattern of configSecurityPatterns) {
    const regex = globalRegex(pattern.regex);
    for (const match of content.matchAll(regex)) {
      const index = match.index ?? 0;
      const { line, column } = locate(index);
      const fingerprint = secretFingerprint(
        `${pattern.id}:${relativePath}:${line}:${column}`
      );

      findings.push(
        patternFinding(pattern, relativePath, line, column, fingerprint)
      );
    }
  }

  return findings;
}

/** Builds a finding from a matched security configuration pattern. */
function patternFinding(
  pattern: SecurityPattern,
  relativePath: string,
  line: number,
  column: number,
  fingerprint: string
): Finding {
  return {
    id: `${pattern.id}:${relativePath}:${line}:${column}`,
    ruleId: pattern.id,
    title: pattern.title,
    severity: pattern.severity,
    confidence: 'medium',
    category: pattern.category,
    message: pattern.message,
    source: 'security-doctor',
    remediation: { summary: pattern.recommendation },
    location: { file: relativePath, line, column },
    evidence: [
      {
        summary: '[configuration pattern matched]',
        fingerprint
      }
    ]
  };
}

/** Returns a fresh global regex so repeated scans do not share lastIndex. */
function globalRegex(pattern: RegExp): RegExp {
  return new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
  );
}

/** Reports missing baseline HTTP security headers from project configuration. */
function detectMissingSecurityHeaders(relativePaths: string[]): Finding[] {
  const possibleServerFiles = relativePaths.filter(
    (file) =>
      !file.startsWith('dist/') &&
      /server|app|main|index|middleware/i.test(file) &&
      /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(file)
  );

  if (possibleServerFiles.length === 0) return [];

  return securityHeaderNames.map((header) => ({
    id: `TOOLIP-HEADER-VERIFY-${header.toUpperCase().replaceAll('-', '_')}`,
    ruleId: 'TOOLIP-HEADER-VERIFY',
    title: `Verify security header: ${header}`,
    severity: 'info',
    confidence: 'low',
    category: 'security-headers',
    message: `Toolip found server-like files. Confirm that ${header} is configured in production responses.`,
    source: 'security-doctor',
    remediation: {
      summary:
        'Use Helmet or equivalent framework middleware to set secure HTTP response headers.'
    },
    metadata: {
      header,
      heuristic: true
    }
  }));
}
