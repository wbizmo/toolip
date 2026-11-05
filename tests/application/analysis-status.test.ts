import { describe, expect, it } from 'vitest';
import {
  assessExecution,
  decideExit,
  gatedFindings,
  isFailOn
} from '../../src/application/analysis-status.js';
import type { AnalyzerExecutionResult } from '../../src/application/analyzer-runner.js';
import { EXIT_CODES } from '../../src/application/exit-codes.js';
import { coverageOf } from '../../src/contracts/analysis.js';
import type { Finding, FindingSeverity } from '../../src/contracts/finding.js';

const result = (
  over: Partial<AnalyzerExecutionResult> = {}
): AnalyzerExecutionResult => ({
  analyzer: 't',
  durationMs: 1,
  findings: [],
  status: 'ok',
  ...over
});

const finding = (severity: FindingSeverity): Finding => ({
  id: severity,
  ruleId: severity,
  title: severity,
  category: 'x',
  severity,
  confidence: 'high',
  message: severity,
  source: 't'
});

describe('analysis status model (issues #27, #35)', () => {
  it.each(['failed', 'timed_out', 'cancelled'] as const)(
    'treats %s as a failed analysis even with an empty findings list',
    (status) => {
      const assessment = assessExecution(result({ status, error: 'nope' }));
      expect(assessment.state).toBe('failed');
      expect(assessment.reason).toBe('nope');
    }
  );

  it('is complete only when coverage is complete and nothing was left unexplained', () => {
    expect(assessExecution(result()).state).toBe('complete');
    expect(
      assessExecution(
        result({
          coverage: coverageOf({
            eligible: 3,
            scanned: 3,
            skipped: 0,
            failed: 0
          })
        })
      ).state
    ).toBe('complete');
  });

  it('is partial when coverage says so, and when warnings arrive without coverage (unknown is not clean)', () => {
    const partial = assessExecution(
      result({
        coverage: coverageOf({ eligible: 4, scanned: 3, skipped: 1, failed: 0 })
      })
    );
    expect(partial).toMatchObject({
      state: 'partial',
      eligible: 4,
      scanned: 3,
      skipped: 1
    });

    expect(
      assessExecution(result({ warnings: ['a skipped file'] })).state
    ).toBe('partial');
  });

  it('coverageOf distinguishes complete, partial, failed and cancelled runs', () => {
    expect(
      coverageOf({ eligible: 0, scanned: 0, skipped: 0, failed: 0 }).state
    ).toBe('complete');
    expect(
      coverageOf({ eligible: 5, scanned: 2, skipped: 2, failed: 1 }).state
    ).toBe('partial');
    expect(
      coverageOf({ eligible: 5, scanned: 0, skipped: 3, failed: 2 }).state
    ).toBe('failed');
    expect(
      coverageOf({
        eligible: 5,
        scanned: 5,
        skipped: 0,
        failed: 0,
        cancelled: true
      }).state
    ).toBe('partial');
  });

  it('keeps conscious exclusions out of the eligible totals', () => {
    const coverage = coverageOf({
      eligible: 2,
      scanned: 2,
      skipped: 0,
      failed: 0,
      excluded: 40
    });
    expect(coverage.state).toBe('complete');
    expect(coverage.excluded).toBe(40);
  });

  describe('exit-code contract', () => {
    it.each([
      // state, gated findings, failOnIncomplete -> exit
      ['complete', 0, true, EXIT_CODES.ok],
      ['complete', 2, true, EXIT_CODES.findings],
      ['partial', 0, true, EXIT_CODES.incomplete],
      ['partial', 0, false, EXIT_CODES.ok],
      ['partial', 3, true, EXIT_CODES.incomplete],
      ['partial', 3, false, EXIT_CODES.findings],
      ['failed', 0, true, EXIT_CODES.failed],
      ['failed', 5, false, EXIT_CODES.failed]
    ] as const)(
      '%s with %i gated findings (failOnIncomplete=%s) exits %i',
      (state, gated, failOnIncomplete, expected) => {
        expect(decideExit({ state, gated, failOnIncomplete })).toBe(expected);
      }
    );

    it('uses distinct, stable codes', () => {
      expect(Object.values(EXIT_CODES)).toEqual([0, 1, 2, 3, 4]);
    });
  });

  describe('--fail-on gating', () => {
    const findings = (
      ['info', 'low', 'medium', 'high', 'critical'] as const
    ).map(finding);

    it.each([
      ['critical', 1],
      ['high', 2],
      ['medium', 3],
      ['low', 4],
      ['info', 5],
      ['none', 0]
    ] as const)('threshold %s gates %i finding(s)', (failOn, expected) => {
      expect(gatedFindings(findings, failOn)).toHaveLength(expected);
    });

    it('validates the option value', () => {
      expect(isFailOn('high')).toBe(true);
      expect(isFailOn('none')).toBe(true);
      expect(isFailOn('urgent')).toBe(false);
      expect(isFailOn(undefined)).toBe(false);
    });

    // CodeRabbit: `in` accepted inherited names, silently disabling the gate.
    it.each([
      'constructor',
      'toString',
      'valueOf',
      '__proto__',
      'hasOwnProperty'
    ])('rejects inherited property name %s', (value) => {
      expect(isFailOn(value)).toBe(false);
    });

    it('keeps accepting every real severity', () => {
      for (const level of ['critical', 'high', 'medium', 'low', 'info']) {
        expect(isFailOn(level)).toBe(true);
      }
    });
  });
});
