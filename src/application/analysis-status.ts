import type { AnalysisState } from '../contracts/analysis.js';
import type { Finding, FindingSeverity } from '../contracts/finding.js';
import type { AnalyzerExecutionResult } from './analyzer-runner.js';
import { EXIT_CODES, type ExitCode } from './exit-codes.js';

export type AnalysisAssessment = {
  state: AnalysisState;
  reason?: string;
  /** Raw runner status (`ok`, `failed`, `timed_out`, `cancelled`). */
  execution: AnalyzerExecutionResult['status'];
  eligible?: number;
  scanned?: number;
  skipped?: number;
  failed?: number;
};

export type FailOn = FindingSeverity | 'none';

const severityRank: Record<FindingSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

export function isFailOn(value: unknown): value is FailOn {
  return (
    value === 'none' || (typeof value === 'string' && value in severityRank)
  );
}

/** Findings at or above the gate. `none` (or undefined) gates nothing. */
export function gatedFindings(
  findings: readonly Finding[],
  failOn: FailOn | undefined
): Finding[] {
  if (!failOn || failOn === 'none') return [];
  const threshold = severityRank[failOn];
  return findings.filter(
    (finding) => severityRank[finding.severity] >= threshold
  );
}

/**
 * Turns a runner outcome into the canonical state. A failed, timed-out or
 * cancelled run is `failed` regardless of how many findings it returned (an
 * empty list proves nothing). A completed run that reports partial coverage, or
 * carries warnings without coverage (unknown is not clean), is `partial`.
 */
export function assessExecution(
  result: AnalyzerExecutionResult
): AnalysisAssessment {
  if (result.status !== 'ok') {
    return {
      state: 'failed',
      reason: result.error ?? `analyzer ${result.status}`,
      execution: result.status
    };
  }

  const coverage = result.coverage;
  if (coverage) {
    return {
      state: coverage.state,
      reason: coverage.reason,
      execution: 'ok',
      eligible: coverage.eligible,
      scanned: coverage.scanned,
      skipped: coverage.skipped,
      failed: coverage.failed
    };
  }

  if ((result.warnings?.length ?? 0) > 0) {
    return {
      state: 'partial',
      reason: `${result.warnings?.length} warning(s) reported without coverage data`,
      execution: 'ok'
    };
  }

  return { state: 'complete', execution: 'ok' };
}

export function decideExit(input: {
  state: AnalysisState;
  gated: number;
  failOnIncomplete: boolean;
}): ExitCode {
  if (input.state === 'failed') return EXIT_CODES.failed;
  if (input.state === 'partial' && input.failOnIncomplete)
    return EXIT_CODES.incomplete;
  if (input.gated > 0) return EXIT_CODES.findings;
  return EXIT_CODES.ok;
}

export function describeAssessment(assessment: AnalysisAssessment): string {
  const counts =
    assessment.eligible === undefined
      ? ''
      : ` (${assessment.scanned ?? 0}/${assessment.eligible} eligible scanned, ${assessment.skipped ?? 0} skipped, ${assessment.failed ?? 0} failed)`;
  const reason = assessment.reason ? `: ${assessment.reason}` : '';
  return `${assessment.state.toUpperCase()}${counts}${reason}`;
}

/** JSON-safe form included in every structured analyzer output. */
export function assessmentJson(
  assessment: AnalysisAssessment
): Record<string, unknown> {
  return {
    state: assessment.state,
    complete: assessment.state === 'complete',
    execution: assessment.execution,
    reason: assessment.reason,
    eligible: assessment.eligible,
    scanned: assessment.scanned,
    skipped: assessment.skipped,
    failed: assessment.failed
  };
}

/**
 * Shared tail for analyzer-facing commands: prints a status line when the run
 * is not complete, applies the exit-code contract and returns it. A clean
 * "nothing found" message must only be printed when `state === 'complete'`.
 */
export function finishAnalysis(input: {
  assessment: AnalysisAssessment;
  findings: readonly Finding[];
  failOn?: FailOn;
  failOnIncomplete?: boolean;
  quiet?: boolean;
}): ExitCode {
  const gated = gatedFindings(input.findings, input.failOn);
  const code = decideExit({
    state: input.assessment.state,
    gated: gated.length,
    failOnIncomplete: input.failOnIncomplete ?? true
  });

  if (!input.quiet && input.assessment.state !== 'complete') {
    console.error(`Analysis ${describeAssessment(input.assessment)}`);
    console.error(
      'This result is not an all-clear: findings below may be missing. See docs/ANALYSIS-STATUS.md.'
    );
  }

  process.exitCode = code;
  return code;
}
