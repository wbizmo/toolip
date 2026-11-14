import { describe, expect, it } from 'vitest';
import type { AnalysisCoverage } from '../../src/contracts/analysis.js';
import type { Finding } from '../../src/contracts/finding.js';
import {
  compareHistoryEntries,
  findingFingerprint,
  historyFindingRecords,
  remediationSla
} from '../../src/core/history/baseline.js';
import type { HistoryEntry } from '../../src/core/history/types.js';
import { renderHistoryDelta } from '../../src/core/history/report.js';

const complete: AnalysisCoverage = {
  state: 'complete',
  eligible: 10,
  scanned: 10,
  skipped: 0,
  failed: 0
};

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'rule:file:10:4',
    ruleId: 'TLP-TEST-001',
    title: 'Test security issue',
    category: 'configuration',
    severity: 'high',
    confidence: 'high',
    message: 'Test finding',
    source: 'fixture',
    location: { file: '/project/src/app.ts', line: 10, column: 4 },
    metadata: { nodeKind: 'CallExpression' },
    ...overrides
  };
}

function historyEntry(
  id: string,
  fingerprints: string[],
  coverage: AnalysisCoverage = complete
): HistoryEntry {
  return {
    id,
    createdAt: '2026-11-06T00:00:00.000Z',
    toolipVersion: '2.2.1',
    command: 'scan',
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    findingIds: [],
    findingFingerprints: fingerprints,
    coverage
  };
}

describe('finding baselines and remediation SLAs', () => {
  it('keeps a fingerprint stable across line movement and distinguishes installed instances', () => {
    const first = finding();
    const moved = finding({
      id: 'rule:file:91:4',
      location: { file: '/project/src/app.ts', line: 91, column: 4 }
    });
    expect(findingFingerprint(first, '/project')).toBe(
      findingFingerprint(moved, '/project')
    );
    expect(
      findingFingerprint(
        finding({
          metadata: {
            package: 'example',
            installedVersion: '1.0.0',
            installPath: 'node_modules/a/node_modules/example'
          }
        }),
        '/project'
      )
    ).not.toBe(
      findingFingerprint(
        finding({
          metadata: {
            package: 'example',
            installedVersion: '1.0.0',
            installPath: 'node_modules/example'
          }
        }),
        '/project'
      )
    );
  });

  it('only reports fixed findings when both baseline scans have complete coverage', () => {
    const baseline = historyEntry('baseline', ['old', 'same']);
    const current = historyEntry('current', ['same', 'new']);
    expect(compareHistoryEntries(current, baseline)).toMatchObject({
      new: ['new'],
      fixed: ['old'],
      unchanged: ['same'],
      unknown: [],
      coverageComparable: true
    });

    const partial = historyEntry('partial', ['same', 'new'], {
      ...complete,
      state: 'partial',
      reason: 'snapshot missing'
    });
    expect(compareHistoryEntries(partial, baseline)).toMatchObject({
      new: [],
      fixed: [],
      unchanged: ['same'],
      unknown: ['new', 'old'],
      coverageComparable: false
    });
  });

  it('preserves first-seen timestamps and computes configurable overdue SLAs', () => {
    const record = {
      fingerprint: 'finding-a',
      ruleId: 'TLP-TEST-001',
      severity: 'high' as const,
      firstSeenAt: '2026-10-01T00:00:00.000Z'
    };
    const previous = {
      ...historyEntry('previous', [record.fingerprint]),
      findingRecords: [record]
    };
    const records = historyFindingRecords({
      findings: [finding()],
      root: '/project',
      createdAt: '2026-11-06T00:00:00.000Z',
      previous: {
        ...previous,
        findingRecords: [
          {
            ...record,
            fingerprint: findingFingerprint(finding(), '/project')
          }
        ]
      }
    });
    expect(records[0]?.firstSeenAt).toBe(record.firstSeenAt);

    const entry = {
      ...historyEntry('sla', []),
      findingRecords: [record]
    };
    expect(
      remediationSla(
        entry,
        { critical: 1, high: 7, medium: 30, low: 90, info: 180 },
        new Date('2026-11-06T00:00:00.000Z')
      )
    ).toMatchObject([
      {
        fingerprint: 'finding-a',
        dueAt: '2026-10-08T00:00:00.000Z',
        overdue: true
      }
    ]);
  });

  it('does not mark an SLA overdue at the exact deadline boundary', () => {
    const record = {
      fingerprint: 'boundary-finding',
      ruleId: 'TLP-TEST-001',
      severity: 'high' as const,
      firstSeenAt: '2026-11-01T00:00:00.000Z'
    };
    const entry = {
      ...historyEntry('boundary', [record.fingerprint]),
      findingRecords: [record]
    };
    const policy = { critical: 1, high: 7, medium: 30, low: 90, info: 180 };
    expect(
      remediationSla(entry, policy, new Date('2026-11-08T00:00:00.000Z'))[0]
        ?.overdue
    ).toBe(false);
    expect(
      remediationSla(entry, policy, new Date('2026-11-08T00:00:00.001Z'))[0]
        ?.overdue
    ).toBe(true);
  });

  it('renders complete deltas as Markdown, escaped HTML and SARIF', () => {
    const baseline = historyEntry('base-1', ['fixed-fingerprint', 'same']);
    baseline.findingRecords = [
      {
        fingerprint: 'fixed-fingerprint',
        ruleId: 'TLP-OLD-001',
        severity: 'high',
        firstSeenAt: baseline.createdAt
      },
      {
        fingerprint: 'same',
        ruleId: 'TLP-SAME-001',
        severity: 'low',
        firstSeenAt: baseline.createdAt
      }
    ];
    const current = historyEntry('current', ['new-fingerprint', 'same']);
    const unchangedRecord = baseline.findingRecords?.[1];
    if (!unchangedRecord) throw new Error('history fixture is incomplete');
    current.findingRecords = [
      {
        fingerprint: 'new-fingerprint',
        ruleId: 'TLP-NEW-001',
        severity: 'critical',
        firstSeenAt: current.createdAt
      },
      unchangedRecord
    ];
    const delta = compareHistoryEntries(current, baseline);
    const markdown = renderHistoryDelta({
      delta,
      current,
      baseline,
      format: 'markdown'
    });
    const html = renderHistoryDelta({
      delta,
      current,
      baseline,
      format: 'html'
    });
    const sarif = JSON.parse(
      renderHistoryDelta({ delta, current, baseline, format: 'sarif' })
    ) as {
      runs: Array<{
        results: Array<{
          baselineState?: string;
          properties: { deltaState: string };
        }>;
      }>;
    };

    expect(markdown).toContain('New (1)');
    expect(markdown).toContain('Fixed (1)');
    expect(html).toContain('Coverage comparable: true');
    expect(
      sarif.runs[0]?.results.map((item) => item.properties.deltaState)
    ).toEqual(['fixed', 'new', 'unchanged']);
    expect(
      sarif.runs[0]?.results.find((item) => item.baselineState === 'absent')
    ).toBeDefined();
  });

  it('renders incomplete comparisons as unknown and never fixed', () => {
    const baseline = historyEntry('base</code><script>', ['missing']);
    const current = historyEntry('current', [], {
      ...complete,
      state: 'partial',
      reason: 'files were skipped'
    });
    const delta = compareHistoryEntries(current, baseline);
    const html = renderHistoryDelta({
      delta,
      current,
      baseline,
      format: 'html'
    });
    const json = JSON.parse(
      renderHistoryDelta({ delta, current, baseline, format: 'json' })
    ) as { counts: { fixed: number; unknown: number } };

    expect(delta.fixed).toEqual([]);
    expect(json.counts).toMatchObject({ fixed: 0, unknown: 1 });
    expect(html).toContain('base&lt;/code&gt;&lt;script&gt;');
    expect(html).not.toContain('<script>');
  });
});
