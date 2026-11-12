import { realpath } from 'node:fs/promises';
import {
  coverageOf,
  type AnalysisCoverage,
  type AnalysisState
} from '../contracts/analysis.js';
import type { Analyzer, AnalyzerCache } from '../contracts/analyzer.js';
import type { Finding } from '../contracts/finding.js';
import { OsvVulnerabilityAnalyzer } from '../analyzers/vulnerability/osv-analyzer.js';
import {
  analyzePackageHealth,
  type PackageHealthAnalysis
} from '../core/package-health-analysis.js';
import {
  calculateDependencyHealthFromPackages,
  calculateFindingHealth,
  calculateScore,
  measuredDimension,
  unmeasuredDimension,
  type DependencyHealthBreakdown,
  type ScoreDimension,
  type ToolipScore
} from '../core/score.js';
import {
  scanDependencies,
  type DependencyScanResult
} from '../core/dependency-scan.js';
import { runSecurityDoctor } from '../core/security-doctor.js';
import { runGitAudit } from '../core/git-audit.js';
import {
  analyzeLicenses,
  type LicenseAnalysisResult
} from '../core/license-analysis.js';
import type { ScannerContext } from '../core/scanner-context.js';
import {
  createScanBudget,
  type ScanBudgetOptions
} from '../core/scan-budget.js';
import { AnalyzerRunner } from './analyzer-runner.js';
import {
  dependencyFileSourceFromSnapshot,
  createProjectSnapshot,
  isScannerContextFromSnapshot,
  scannerContextFromSnapshot,
  type ProjectSnapshot
} from './project-snapshot.js';
import type { AnalysisResultCache } from './task-scheduler.js';
import type { AnalysisTask } from './task-scheduler.js';
import { runTaskDag } from './task-scheduler.js';
import type { VerifiedRulePack } from '../core/rule-packs.js';
import type { WasmAnalyzerPlugin } from '../core/analyzer-plugin.js';
import type { GoCommandRunner } from '../core/dependencies/go-module-graph.js';
import type { PythonTargetProfile } from '../core/dependencies/python-target.js';
import type { GoTargetProfile } from '../core/dependencies/go-target.js';
import type { ReportEvidenceSubject } from '../core/report-signature.js';
import type {
  NpmProvenancePolicy,
  NpmProvenanceVerification
} from '../providers/npm/provenance.js';

export type SecurityScorecardServices = {
  dependencyScan?: typeof scanDependencies;
  doctor?: typeof runSecurityDoctor;
  gitAudit?: typeof runGitAudit;
  vulnerabilityAnalyzer?: Analyzer;
  packageHealth?: typeof analyzePackageHealth;
  licenseAnalysis?: typeof analyzeLicenses;
};

export type SecurityScorecardOptions = {
  /** Shared deadline and request limits for the whole scorecard (issue #48). */
  budget?: ScanBudgetOptions;
  /** Local snapshot cache shared with advisory providers. */
  cache?: AnalyzerCache;
  /** Prohibit all registry/advisory network requests. */
  offline?: boolean;
  /** Explicitly run the Go tool on captured metadata to resolve MVS. */
  allowGoToolExecution?: boolean;
  /** Resolve Python markers/extras for exactly one declared target profile. */
  pythonTarget?: PythonTargetProfile;
  /** Select platform-specific files in vendored Go module source. */
  goTarget?: GoTargetProfile;
  /** Injectable Go process boundary for verified host integrations/tests. */
  goCommandRunner?: GoCommandRunner;
  /** Maximum age allowed for cached OSV records. */
  maxAdvisoryAgeMs?: number;
  /** Explicit consent to send scoped npm package names to public providers. */
  allowPublicScope?: boolean;
  /** Opt-in operator-owned trust rules for exact npm provenance verification. */
  npmProvenancePolicy?: NpmProvenancePolicy;
  /** Opt in to npm publisher, maintenance and lifecycle-history review signals. */
  includePackageHealth?: boolean;
  /** Add deps.dev license findings to the immutable scan result. */
  includeLicenseAnalysis?: boolean;
  rulePacks?: readonly VerifiedRulePack[];
  analyzerPlugins?: readonly WasmAnalyzerPlugin[];
  enableExecutablePlugins?: boolean;
  previousSnapshot?: ProjectSnapshot;
  /** Reuse a caller's bounded immutable capture rather than taking a second snapshot. */
  projectSnapshot?: ProjectSnapshot;
  analysisCache?: AnalysisResultCache;
  /** Reuse discovery already performed by the enclosing command. */
  scannerContext?: ScannerContext;
};

export type SecurityScorecardResult = {
  /** Overall completeness: any unmeasured dimension makes the run partial or failed. */
  analysis: { state: AnalysisState; reasons: string[] };
  /** Summed dependency and file coverage; other dimensions use analysis reasons. */
  coverage: AnalysisCoverage;
  score: ToolipScore;
  dependencyHealth?: DependencyHealthBreakdown;
  dependencySummary?: DependencyScanResult['summary'];
  npmProvenance?: NpmProvenanceVerification[];
  packageHealth?: PackageHealthAnalysis;
  licenseAnalysis?: LicenseAnalysisResult;
  findings: Finding[];
  warnings: string[];
  snapshotId: string;
  evidenceSubject: ReportEvidenceSubject;
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

export async function buildSecurityScorecard(
  root: string,
  services: SecurityScorecardServices = {},
  options: SecurityScorecardOptions = {}
): Promise<SecurityScorecardResult> {
  const dependencyScan = services.dependencyScan ?? scanDependencies;
  const doctor = services.doctor ?? runSecurityDoctor;
  const gitAudit = services.gitAudit ?? runGitAudit;
  const vulnerabilityAnalyzer =
    services.vulnerabilityAnalyzer ?? new OsvVulnerabilityAnalyzer();
  const packageHealthAnalyzer = services.packageHealth ?? analyzePackageHealth;
  const licenseAnalyzer = services.licenseAnalysis ?? analyzeLicenses;
  const scanRoot = options.scannerContext?.root ?? root;
  const runner = new AnalyzerRunner({ concurrency: 1, timeoutMs: 60_000 });
  const { budget, dispose } = createScanBudget(options.budget);
  let context: Awaited<ReturnType<typeof scannerContextFromSnapshot>>;
  let projectSnapshot: ProjectSnapshot;
  try {
    const [canonicalRoot, requestedRoot] = await Promise.all([
      realpath(scanRoot),
      realpath(root)
    ]);
    if (canonicalRoot !== requestedRoot) {
      throw new Error('scanner context root does not match the scorecard root');
    }
    projectSnapshot =
      options.projectSnapshot ??
      (await createProjectSnapshot(scanRoot, {
        signal: budget.signal,
        discoveredFiles: options.scannerContext?.files,
        previous: options.previousSnapshot
      }));
    if (projectSnapshot.root !== canonicalRoot) {
      throw new Error('project snapshot root does not match the scan root');
    }
    // Capture first, then build the shared context from those captured bytes.
    // This avoids profiling live files before the snapshot and then rereading
    // them, while ensuring every downstream analyzer sees one immutable input.
    context =
      options.scannerContext &&
      isScannerContextFromSnapshot(options.scannerContext, projectSnapshot)
        ? options.scannerContext
        : await scannerContextFromSnapshot(projectSnapshot);
  } catch (error) {
    dispose();
    throw error;
  }

  type ScorecardTaskValue =
    | { kind: 'dependencies'; value: DependencyScanResult }
    | {
        kind: 'doctor';
        value: Awaited<ReturnType<typeof runSecurityDoctor>>;
      }
    | { kind: 'git'; value: Awaited<ReturnType<typeof runGitAudit>> }
    | {
        kind: 'vulnerability';
        value: Awaited<ReturnType<AnalyzerRunner['run']>>;
      }
    | { kind: 'packageHealth'; value: PackageHealthAnalysis }
    | { kind: 'licenses'; value: LicenseAnalysisResult };
  let dependencyOutcome: PromiseSettledResult<DependencyScanResult>;
  let doctorOutcome: PromiseSettledResult<
    Awaited<ReturnType<typeof runSecurityDoctor>>
  >;
  let gitOutcome: PromiseSettledResult<Awaited<ReturnType<typeof runGitAudit>>>;
  let vulnerabilityOutcome: PromiseSettledResult<
    Awaited<ReturnType<AnalyzerRunner['run']>>
  >;
  let packageHealthOutcome:
    PromiseSettledResult<PackageHealthAnalysis> | undefined;
  let licenseOutcome: PromiseSettledResult<LicenseAnalysisResult> | undefined;

  try {
    const fileSource = dependencyFileSourceFromSnapshot(projectSnapshot);
    // A single DAG owns the scan's task lifecycle and cancellation. Tasks are
    // independent today, while the graph contract lets future dependency
    // stages add explicit edges without forking separate orchestration paths.
    let dependencyFacts: DependencyScanResult | undefined;
    const tasks: AnalysisTask<ScorecardTaskValue>[] = [
      {
        id: 'dependency-health',
        run: async () => {
          const value = await dependencyScan(context.root, {
            budget,
            offline: options.offline,
            allowPublicScope: options.allowPublicScope,
            npmProvenancePolicy: options.npmProvenancePolicy,
            fileSource,
            inventoryCache: options.analysisCache,
            inventoryCacheKey: projectSnapshot.lockGraphDigest
          });
          dependencyFacts = value;
          return { kind: 'dependencies', value };
        }
      },
      {
        id: 'security-doctor',
        run: async (signal) => ({
          kind: 'doctor',
          value: await doctor(context, {
            signal,
            snapshot: projectSnapshot,
            analysisCache: options.analysisCache,
            rulePacks: options.rulePacks,
            analyzerPlugins: options.analyzerPlugins,
            enableExecutablePlugins: options.enableExecutablePlugins
          })
        })
      },
      {
        id: 'git-audit',
        run: async () => ({ kind: 'git', value: await gitAudit(context) })
      },
      {
        id: 'vulnerability-intelligence',
        run: async (signal) => ({
          kind: 'vulnerability',
          value: await runner.run([vulnerabilityAnalyzer], {
            root: context.root,
            signal,
            cache: options.cache,
            options: {
              offline: options.offline ?? false,
              allowGoToolExecution: options.allowGoToolExecution === true,
              pythonTarget: options.pythonTarget,
              goTarget: options.goTarget,
              goCommandRunner: options.goCommandRunner,
              maxAdvisoryAgeMs: options.maxAdvisoryAgeMs,
              allowPublicScope: options.allowPublicScope === true,
              scannerContext: context,
              snapshot: projectSnapshot,
              dependencyFileSource: fileSource
            }
          })
        })
      }
    ];
    if (options.includePackageHealth) {
      tasks.push({
        id: 'package-health-anomalies',
        dependsOn: ['dependency-health'],
        run: async (signal) => ({
          kind: 'packageHealth',
          value: await packageHealthAnalyzer(
            dependencyFacts?.identities ?? [],
            {
              signal,
              offline: options.offline,
              allowPublicScope: options.allowPublicScope,
              concurrency: Math.max(
                1,
                Math.floor(budget.maxConcurrentRequests / 2)
              ),
              requestTimeoutMs: budget.requestTimeoutMs
            }
          )
        })
      });
    }
    if (options.includeLicenseAnalysis) {
      tasks.push({
        id: 'license-analysis',
        dependsOn: ['dependency-health'],
        run: async (signal) => ({
          kind: 'licenses',
          value: await licenseAnalyzer(context.root, undefined, signal, {
            offline: options.offline,
            allowPublicScope: options.allowPublicScope,
            concurrency: Math.max(
              1,
              Math.floor(budget.maxConcurrentRequests / 2)
            ),
            fileSource,
            ...(dependencyFacts?.identities
              ? { inventory: dependencyFacts.identities }
              : {}),
            ...(dependencyFacts
              ? {
                  inventoryComplete: !dependencyFacts.failures.some(
                    (failure) => failure.kind === 'unresolved'
                  ),
                  inventoryWarnings: dependencyFacts.failures
                    .filter((failure) => failure.kind === 'unresolved')
                    .map((failure) => failure.message)
                }
              : {})
          })
        })
      });
    }
    const outcomes = await runTaskDag<ScorecardTaskValue>(tasks, {
      concurrency: 4,
      signal: budget.signal
    });
    const settle = <T extends ScorecardTaskValue['kind']>(kind: T) => {
      const outcome = outcomes.find(
        (item) => item.state === 'complete' && item.value.kind === kind
      );
      if (outcome?.state === 'complete') {
        return {
          status: 'fulfilled' as const,
          value: outcome.value.value as Extract<
            ScorecardTaskValue,
            { kind: T }
          >['value']
        };
      }
      const failed = outcomes.find(
        (item) =>
          item.id ===
          (
            {
              dependencies: 'dependency-health',
              doctor: 'security-doctor',
              git: 'git-audit',
              vulnerability: 'vulnerability-intelligence',
              packageHealth: 'package-health-anomalies',
              licenses: 'license-analysis'
            } satisfies Record<ScorecardTaskValue['kind'], string>
          )[kind]
      );
      return {
        status: 'rejected' as const,
        reason:
          failed?.state === 'failed'
            ? new Error(failed.error)
            : new Error(
                failed?.state === 'cancelled' || failed?.state === 'blocked'
                  ? failed.reason
                  : 'analysis task did not return a result'
              )
      };
    };
    dependencyOutcome = settle('dependencies');
    doctorOutcome = settle('doctor');
    gitOutcome = settle('git');
    vulnerabilityOutcome = settle('vulnerability');
    packageHealthOutcome = options.includePackageHealth
      ? settle('packageHealth')
      : undefined;
    licenseOutcome = options.includeLicenseAnalysis
      ? settle('licenses')
      : undefined;
  } finally {
    dispose();
  }

  const vulnerabilityExecution =
    vulnerabilityOutcome.status === 'fulfilled'
      ? vulnerabilityOutcome.value[0]
      : undefined;

  let dependencyHealth: DependencyHealthBreakdown | undefined;
  let dependencySummary: DependencyScanResult['summary'] | undefined;
  let npmProvenance: NpmProvenanceVerification[] | undefined;
  const packageHealthResult =
    packageHealthOutcome?.status === 'fulfilled'
      ? packageHealthOutcome.value
      : undefined;
  const licenseAnalysisResult =
    licenseOutcome?.status === 'fulfilled' ? licenseOutcome.value : undefined;
  let dependencyDimension: ScoreDimension;
  const findings: Finding[] = [];
  const warnings: string[] = [];

  if (packageHealthResult) {
    findings.push(...packageHealthResult.findings);
    warnings.push(...packageHealthResult.warnings);
  }
  if (licenseAnalysisResult) {
    findings.push(...licenseAnalysisResult.findings);
    warnings.push(...licenseAnalysisResult.warnings);
  }

  if (dependencyOutcome.status === 'rejected') {
    dependencyDimension = failedDimension(
      dependencyOutcome.reason,
      'Dependency analysis failed.'
    );
  } else {
    dependencySummary = dependencyOutcome.value.summary;
    npmProvenance = dependencyOutcome.value.npmProvenance;
    findings.push(...dependencyOutcome.value.findings);
    const dependencyCoverage = dependencyOutcome.value.coverage;

    // OSV runs independently of registry lookups: a completed run's findings
    // and warnings must survive partial registry coverage.
    if (vulnerabilityExecution?.status === 'ok') {
      findings.push(...vulnerabilityExecution.findings);
    }
    warnings.push(...(vulnerabilityExecution?.warnings ?? []));

    if (dependencyCoverage && dependencyCoverage.state !== 'complete') {
      // Some registry lookups failed or timed out: dependency health is NOT
      // measured. Partial packages are never averaged into a healthy score.
      const failures = dependencyOutcome.value.failures ?? [];
      const timedOut = failures.some((failure) => failure.kind === 'timed_out');
      const sample = failures
        .slice(0, 3)
        .map((failure) =>
          failure.version
            ? `${failure.name}@${failure.version}`
            : `${failure.name}@${failure.requirement ?? 'unknown'} (unresolved)`
        )
        .join(', ');
      const osvNote =
        vulnerabilityExecution && vulnerabilityExecution.status !== 'ok'
          ? `; vulnerability analysis ${vulnerabilityExecution.status}: ${vulnerabilityExecution.error ?? 'did not complete successfully'}`
          : '';
      dependencyDimension = unmeasuredDimension(
        dependencyCoverage.state === 'failed' || !timedOut
          ? 'failed'
          : 'timed_out',
        `${dependencyCoverage.reason ?? 'registry lookups did not complete'}${sample ? ` (for example ${sample})` : ''}${osvNote}`
      );
      warnings.push(
        ...failures
          .slice(0, 10)
          .map(
            (failure) =>
              `${failure.name}@${failure.version ?? failure.requirement ?? 'unknown'}: ${failure.kind} - ${failure.message}`
          )
      );
    } else if (!vulnerabilityExecution) {
      dependencyDimension = unmeasuredDimension(
        'failed',
        'Vulnerability analysis did not return a result.'
      );
    } else if (vulnerabilityExecution.status !== 'ok') {
      dependencyDimension = unmeasuredDimension(
        vulnerabilityExecution.status,
        vulnerabilityExecution.error ??
          'Vulnerability analysis did not complete successfully.'
      );
    } else if (
      vulnerabilityExecution.coverage?.state !== undefined &&
      vulnerabilityExecution.coverage.state !== 'complete'
    ) {
      dependencyDimension = unmeasuredDimension(
        vulnerabilityExecution.coverage.state === 'failed'
          ? 'failed'
          : 'unavailable',
        vulnerabilityExecution.coverage.reason ??
          'Offline advisory records are missing or stale.'
      );
    } else if (
      dependencyOutcome.value.npmProvenance?.some(
        (verification) => verification.status !== 'verified'
      )
    ) {
      const unverified = dependencyOutcome.value.npmProvenance.filter(
        (verification) => verification.status !== 'verified'
      );
      const sample = unverified
        .slice(0, 3)
        .map((verification) => `${verification.name}@${verification.version}`)
        .join(', ');
      dependencyDimension = unmeasuredDimension(
        'unavailable',
        `npm publisher provenance is not verified for ${unverified.length} package(s)${sample ? ` (for example ${sample})` : ''}.`
      );
    } else {
      dependencyHealth = calculateDependencyHealthFromPackages(
        dependencyOutcome.value.packages,
        vulnerabilityExecution.findings
      );
      dependencyDimension = measuredDimension(
        dependencyHealth.score,
        dependencyOutcome.value.findings.length +
          vulnerabilityExecution.findings.length
      );
    }
  }

  let secretDimension: ScoreDimension;
  let configurationDimension: ScoreDimension;

  if (doctorOutcome.status === 'rejected') {
    secretDimension = failedDimension(
      doctorOutcome.reason,
      'Secret analysis failed.'
    );
    configurationDimension = failedDimension(
      doctorOutcome.reason,
      'Configuration analysis failed.'
    );
  } else {
    const doctorResult = doctorOutcome.value;
    findings.push(...doctorResult.findings);
    warnings.push(...(doctorResult.warnings ?? []));

    if (
      doctorResult.summary.filesSkipped > 0 ||
      (doctorResult.coverage !== undefined &&
        doctorResult.coverage.state !== 'complete')
    ) {
      const reason =
        `${doctorResult.summary.filesSkipped} eligible file(s) were not scanned; ` +
        'security hygiene cannot be scored completely.';
      secretDimension = unmeasuredDimension('unavailable', reason);
      configurationDimension = unmeasuredDimension('unavailable', reason);
    } else {
      const secrets = doctorResult.findings.filter(
        (finding) => finding.category === 'secrets'
      );
      const configuration = doctorResult.findings.filter(
        (finding) =>
          finding.category === 'configuration' ||
          finding.category === 'security-headers'
      );
      secretDimension = measuredDimension(
        calculateFindingHealth(secrets),
        secrets.length
      );
      configurationDimension = measuredDimension(
        calculateFindingHealth(configuration),
        configuration.length
      );
    }
  }

  let gitDimension: ScoreDimension;
  if (gitOutcome.status === 'rejected') {
    gitDimension = failedDimension(
      gitOutcome.reason,
      'Git safety analysis failed.'
    );
  } else {
    findings.push(...gitOutcome.value.findings);
    gitDimension =
      gitOutcome.value.summary.ignoreStatus === 'unknown'
        ? unmeasuredDimension(
            'unavailable',
            'Git ignore and tracked-file status could not be observed.'
          )
        : measuredDimension(
            calculateFindingHealth(gitOutcome.value.findings),
            gitOutcome.value.findings.length
          );
  }

  const score = calculateScore({
    dependencyHealth: dependencyDimension,
    secretHygiene: secretDimension,
    configurationSecurity: configurationDimension,
    gitSafety: gitDimension
  });

  const dimensions = [
    ['dependency health', dependencyDimension],
    ['secret hygiene', secretDimension],
    ['configuration security', configurationDimension],
    ['git safety', gitDimension]
  ] as const;
  const unmeasured = dimensions.filter(([, d]) => d.status !== 'measured');
  const analysisReasons = unmeasured.map(
    ([name, d]) => `${name}: ${d.status}${d.reason ? ` - ${d.reason}` : ''}`
  );
  if (packageHealthOutcome?.status === 'rejected') {
    analysisReasons.push(
      `package health: failed - ${
        packageHealthOutcome.reason instanceof Error
          ? packageHealthOutcome.reason.message
          : String(packageHealthOutcome.reason)
      }`
    );
  } else if (
    packageHealthResult?.coverage.state !== undefined &&
    packageHealthResult.coverage.state !== 'complete'
  ) {
    analysisReasons.push(
      `package health: ${packageHealthResult.coverage.state}${
        packageHealthResult.coverage.reason
          ? ` - ${packageHealthResult.coverage.reason}`
          : ''
      }`
    );
  }
  if (licenseOutcome?.status === 'rejected') {
    analysisReasons.push(
      `license analysis: failed - ${
        licenseOutcome.reason instanceof Error
          ? licenseOutcome.reason.message
          : String(licenseOutcome.reason)
      }`
    );
  } else if (
    licenseAnalysisResult?.coverage.state !== undefined &&
    licenseAnalysisResult.coverage.state !== 'complete'
  ) {
    analysisReasons.push(
      `license analysis: ${licenseAnalysisResult.coverage.state}${
        licenseAnalysisResult.coverage.reason
          ? ` - ${licenseAnalysisResult.coverage.reason}`
          : ''
      }`
    );
  }
  const baseAnalysisState =
    unmeasured.length === 0
      ? 'complete'
      : unmeasured.length === dimensions.length
        ? 'failed'
        : 'partial';
  const analysis: SecurityScorecardResult['analysis'] = {
    state:
      baseAnalysisState === 'complete' && analysisReasons.length > 0
        ? 'partial'
        : baseAnalysisState,
    reasons: analysisReasons
  };

  // Only scanners that enumerate inputs contribute numerical coverage.
  // OSV and Git availability are represented by analysis reasons.
  const sources: AnalysisCoverage[] = [];
  if (
    dependencyOutcome.status === 'fulfilled' &&
    dependencyOutcome.value.coverage
  ) {
    sources.push(dependencyOutcome.value.coverage);
  }
  if (doctorOutcome.status === 'fulfilled') {
    const doctorResult = doctorOutcome.value;
    const summary = doctorResult.summary;
    sources.push(
      doctorResult.coverage ??
        coverageOf({
          eligible: summary.filesEligible,
          scanned: summary.filesScanned,
          skipped: Math.max(0, summary.filesSkipped - summary.readFailures),
          failed: summary.readFailures,
          excluded: Math.max(0, summary.filesDiscovered - summary.filesEligible)
        })
    );
  }
  if (licenseAnalysisResult) sources.push(licenseAnalysisResult.coverage);

  const totals = sources.reduce(
    (sum, part) => ({
      eligible: sum.eligible + part.eligible,
      scanned: sum.scanned + part.scanned,
      skipped: sum.skipped + part.skipped,
      failed: sum.failed + part.failed,
      excluded: sum.excluded + (part.excluded ?? 0)
    }),
    { eligible: 0, scanned: 0, skipped: 0, failed: 0, excluded: 0 }
  );
  const coverage: AnalysisCoverage = {
    state: analysis.state,
    ...totals,
    ...(analysis.state === 'complete'
      ? {}
      : { reason: analysis.reasons.join('; ') })
  };

  const capturedSnapshot = projectSnapshot;
  return {
    analysis,
    coverage,
    score,
    dependencyHealth,
    dependencySummary,
    ...(npmProvenance ? { npmProvenance } : {}),
    ...(packageHealthResult ? { packageHealth: packageHealthResult } : {}),
    ...(licenseAnalysisResult
      ? { licenseAnalysis: licenseAnalysisResult }
      : {}),
    findings,
    warnings,
    snapshotId: capturedSnapshot.id,
    analyzerPlugins:
      doctorOutcome.status === 'fulfilled'
        ? doctorOutcome.value.analyzerPlugins
        : [],
    evidenceSubject: {
      ...(capturedSnapshot.gitHeadRevision
        ? { gitRevision: capturedSnapshot.gitHeadRevision }
        : {}),
      ...(capturedSnapshot.gitIndexDigest
        ? { gitIndexDigest: capturedSnapshot.gitIndexDigest }
        : {}),
      sourceTreeDigest: capturedSnapshot.sourceTreeDigest,
      ...(capturedSnapshot.lockGraphDigest
        ? { lockGraphDigest: capturedSnapshot.lockGraphDigest }
        : {}),
      ...(dependencyOutcome.status === 'fulfilled' &&
      dependencyOutcome.value.dependencyGraphDigest
        ? {
            dependencyGraphDigest: dependencyOutcome.value.dependencyGraphDigest
          }
        : {}),
      ...(capturedSnapshot.configDigest
        ? { configDigest: capturedSnapshot.configDigest }
        : {}),
      ...(options.rulePacks?.length
        ? {
            rulePacks: options.rulePacks.map(({ id, sha256, trust, keyId }) =>
              Object.freeze({
                id,
                sha256,
                trust,
                ...(keyId === undefined ? {} : { keyId })
              })
            )
          }
        : {})
    },
    cacheMetrics: {
      hits:
        (doctorOutcome.status === 'fulfilled'
          ? (doctorOutcome.value.cacheMetrics?.hits ?? 0)
          : 0) +
        (dependencyOutcome.status === 'fulfilled' &&
        dependencyOutcome.value.inventoryCacheHit === true
          ? 1
          : 0),
      misses:
        (doctorOutcome.status === 'fulfilled'
          ? (doctorOutcome.value.cacheMetrics?.misses ?? 0)
          : 0) +
        (dependencyOutcome.status === 'fulfilled' &&
        dependencyOutcome.value.inventoryCacheHit === false
          ? 1
          : 0),
      astProjectHits:
        doctorOutcome.status === 'fulfilled'
          ? (doctorOutcome.value.cacheMetrics?.astProjectHits ?? 0)
          : 0,
      astProjectMisses:
        doctorOutcome.status === 'fulfilled'
          ? (doctorOutcome.value.cacheMetrics?.astProjectMisses ?? 0)
          : 0,
      resultCache:
        doctorOutcome.status === 'fulfilled'
          ? (doctorOutcome.value.cacheMetrics?.resultCache ?? {
              hits: 0,
              misses: 0,
              evictions: 0,
              entries: 0,
              retainedSerializedBytes: 0
            })
          : {
              hits: 0,
              misses: 0,
              evictions: 0,
              entries: 0,
              retainedSerializedBytes: 0
            }
    }
  };
}

function failedDimension(error: unknown, fallback: string): ScoreDimension {
  const reason =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : fallback;

  return unmeasuredDimension('failed', reason || fallback);
}
