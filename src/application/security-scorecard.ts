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
import { AnalyzerRunner } from './analyzer-runner.js';

export type SecurityScorecardServices = {
  dependencyScan?: typeof scanDependencies;
  doctor?: typeof runSecurityDoctor;
  gitAudit?: typeof runGitAudit;
  vulnerabilityAnalyzer?: Analyzer;
};

export type SecurityScorecardResult = {
  score: ToolipScore;
  dependencyHealth?: DependencyHealthBreakdown;
  dependencySummary?: DependencyScanResult['summary'];
  findings: Finding[];
  warnings: string[];
};

export async function buildSecurityScorecard(
  root: string,
  services: SecurityScorecardServices = {}
): Promise<SecurityScorecardResult> {
  const dependencyScan = services.dependencyScan ?? scanDependencies;
  const doctor = services.doctor ?? runSecurityDoctor;
  const gitAudit = services.gitAudit ?? runGitAudit;
  const vulnerabilityAnalyzer =
    services.vulnerabilityAnalyzer ?? new OsvVulnerabilityAnalyzer();
  const context = await createScannerContext(root);
  const runner = new AnalyzerRunner({ concurrency: 1, timeoutMs: 60_000 });

  const [dependencyOutcome, doctorOutcome, gitOutcome, vulnerabilityOutcome] =
    await Promise.allSettled([
      dependencyScan(context.root),
      doctor(context),
      gitAudit(context),
      runner.run([vulnerabilityAnalyzer], { root: context.root })
    ]);

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

    if (!vulnerabilityExecution) {
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

  return {
    score,
    dependencyHealth,
    dependencySummary,
    findings,
    warnings
  };
}

function failedDimension(
  error: unknown,
  fallback: string
): ScoreDimension {
  const reason = error instanceof Error
    ? error.message
    : typeof error === 'string'
      ? error
      : fallback;

  return unmeasuredDimension('failed', reason || fallback);
}
