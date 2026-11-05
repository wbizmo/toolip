import type { AnalysisState } from '../contracts/analysis.js';
import type { Analyzer } from '../contracts/analyzer.js';
import type { Finding } from '../contracts/finding.js';
import { OsvVulnerabilityAnalyzer } from '../analyzers/vulnerability/osv-analyzer.js';
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
import { createScannerContext } from '../core/scanner-context.js';
import {
  createScanBudget,
  type ScanBudgetOptions
} from '../core/scan-budget.js';
import { AnalyzerRunner } from './analyzer-runner.js';

export type SecurityScorecardServices = {
  dependencyScan?: typeof scanDependencies;
  doctor?: typeof runSecurityDoctor;
  gitAudit?: typeof runGitAudit;
  vulnerabilityAnalyzer?: Analyzer;
};

export type SecurityScorecardOptions = {
  /** Shared deadline and request limits for the whole scorecard (issue #48). */
  budget?: ScanBudgetOptions;
};

export type SecurityScorecardResult = {
  /** Overall completeness: any unmeasured dimension makes the run partial or failed. */
  analysis: { state: AnalysisState; reasons: string[] };
  score: ToolipScore;
  dependencyHealth?: DependencyHealthBreakdown;
  dependencySummary?: DependencyScanResult['summary'];
  findings: Finding[];
  warnings: string[];
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
  const context = await createScannerContext(root);
  const runner = new AnalyzerRunner({ concurrency: 1, timeoutMs: 60_000 });
  const { budget, dispose } = createScanBudget(options.budget);

  let dependencyOutcome: PromiseSettledResult<DependencyScanResult>;
  let doctorOutcome: PromiseSettledResult<
    Awaited<ReturnType<typeof runSecurityDoctor>>
  >;
  let gitOutcome: PromiseSettledResult<Awaited<ReturnType<typeof runGitAudit>>>;
  let vulnerabilityOutcome: PromiseSettledResult<
    Awaited<ReturnType<AnalyzerRunner['run']>>
  >;

  try {
    // One budget bounds every provider-facing step: registry lookups honor its
    // signal and request limits, and the OSV analyzer is cancelled with it.
    [dependencyOutcome, doctorOutcome, gitOutcome, vulnerabilityOutcome] =
      await Promise.allSettled([
        dependencyScan(context.root, { budget }),
        doctor(context, { signal: budget.signal }),
        gitAudit(context),
        runner.run([vulnerabilityAnalyzer], {
          root: context.root,
          signal: budget.signal
        })
      ]);
  } finally {
    dispose();
  }

  const vulnerabilityExecution =
    vulnerabilityOutcome.status === 'fulfilled'
      ? vulnerabilityOutcome.value[0]
      : undefined;

  let dependencyHealth: DependencyHealthBreakdown | undefined;
  let dependencySummary: DependencyScanResult['summary'] | undefined;
  let dependencyDimension: ScoreDimension;
  const findings: Finding[] = [];
  const warnings: string[] = [];

  if (dependencyOutcome.status === 'rejected') {
    dependencyDimension = failedDimension(
      dependencyOutcome.reason,
      'Dependency analysis failed.'
    );
  } else {
    dependencySummary = dependencyOutcome.value.summary;
    findings.push(...dependencyOutcome.value.findings);
    const dependencyCoverage = dependencyOutcome.value.coverage;

    if (dependencyCoverage && dependencyCoverage.state !== 'complete') {
      // Some registry lookups failed or timed out: dependency health is NOT
      // measured. Partial packages are never averaged into a healthy score.
      const failures = dependencyOutcome.value.failures ?? [];
      const timedOut = failures.some((failure) => failure.kind === 'timed_out');
      const sample = failures
        .slice(0, 3)
        .map((failure) => `${failure.name}@${failure.version}`)
        .join(', ');
      dependencyDimension = unmeasuredDimension(
        dependencyCoverage.state === 'failed' || !timedOut
          ? 'failed'
          : 'timed_out',
        `${dependencyCoverage.reason ?? 'registry lookups did not complete'}${sample ? ` (for example ${sample})` : ''}`
      );
      warnings.push(
        ...failures
          .slice(0, 10)
          .map(
            (failure) =>
              `${failure.name}@${failure.version}: ${failure.kind} - ${failure.message}`
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
      warnings.push(...(vulnerabilityExecution.warnings ?? []));
    } else {
      findings.push(...vulnerabilityExecution.findings);
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

    if (doctorResult.summary.filesSkipped > 0) {
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
    gitDimension = measuredDimension(
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
  const analysis: SecurityScorecardResult['analysis'] = {
    state:
      unmeasured.length === 0
        ? 'complete'
        : unmeasured.length === dimensions.length
          ? 'failed'
          : 'partial',
    reasons: unmeasured.map(
      ([name, d]) => `${name}: ${d.status}${d.reason ? ` - ${d.reason}` : ''}`
    )
  };

  return {
    analysis,
    score,
    dependencyHealth,
    dependencySummary,
    findings,
    warnings
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
