import type { FindingSeverity } from '../../contracts/finding.js';
import { sanitizeOutput } from '../safe-output.js';
import type { BaselineDelta } from './baseline.js';
import type { HistoryEntry, HistoryFindingRecord } from './types.js';

export type HistoryDeltaFormat = 'json' | 'markdown' | 'html' | 'sarif';

type DeltaState = 'new' | 'fixed' | 'unchanged' | 'unknown';

type DeltaRow = {
  state: DeltaState;
  fingerprint: string;
  record?: HistoryFindingRecord;
};

/** Renders a history comparison without treating incomplete scans as fixes. */
export function renderHistoryDelta(input: {
  delta: BaselineDelta;
  current: HistoryEntry;
  baseline: HistoryEntry;
  format: HistoryDeltaFormat;
}): string {
  const { delta, current, baseline, format } = input;
  const rows = deltaRows(delta, current, baseline);
  if (format === 'json') {
    return `${JSON.stringify(
      sanitizeOutput({
        schemaVersion: 1,
        comparisonBase: delta.comparisonBase,
        coverageComparable: delta.coverageComparable,
        counts: countStates(rows),
        findings: rows
      }),
      null,
      2
    )}\n`;
  }
  if (format === 'markdown') return renderMarkdown(delta, rows);
  if (format === 'html') return renderHtml(delta, rows);
  return `${JSON.stringify(createSarif(delta, current, rows), null, 2)}\n`;
}

function deltaRows(
  delta: BaselineDelta,
  current: HistoryEntry,
  baseline: HistoryEntry
): DeltaRow[] {
  const currentRecords = new Map(
    (current.findingRecords ?? []).map((record) => [record.fingerprint, record])
  );
  const baselineRecords = new Map(
    (baseline.findingRecords ?? []).map((record) => [
      record.fingerprint,
      record
    ])
  );
  return [
    ...delta.new.map((fingerprint) => ({
      state: 'new' as const,
      fingerprint,
      record: currentRecords.get(fingerprint)
    })),
    ...delta.fixed.map((fingerprint) => ({
      state: 'fixed' as const,
      fingerprint,
      record: baselineRecords.get(fingerprint)
    })),
    ...delta.unchanged.map((fingerprint) => ({
      state: 'unchanged' as const,
      fingerprint,
      record:
        currentRecords.get(fingerprint) ?? baselineRecords.get(fingerprint)
    })),
    ...delta.unknown.map((fingerprint) => ({
      state: 'unknown' as const,
      fingerprint,
      record:
        currentRecords.get(fingerprint) ?? baselineRecords.get(fingerprint)
    }))
  ].sort(
    (left, right) =>
      left.state.localeCompare(right.state) ||
      left.fingerprint.localeCompare(right.fingerprint)
  );
}

function countStates(rows: DeltaRow[]): Record<DeltaState, number> {
  const counts: Record<DeltaState, number> = {
    new: 0,
    fixed: 0,
    unchanged: 0,
    unknown: 0
  };
  for (const row of rows) counts[row.state] += 1;
  return counts;
}

function renderMarkdown(delta: BaselineDelta, rows: DeltaRow[]): string {
  const counts = countStates(rows);
  const sections = (['new', 'fixed', 'unchanged', 'unknown'] as const)
    .map((state) => {
      const selected = rows.filter((row) => row.state === state);
      const body = selected.length
        ? selected
            .map(
              (row) =>
                `- ${escapeMarkdown(row.record?.ruleId ?? 'finding')} — \`${row.fingerprint}\``
            )
            .join('\n')
        : '- None';
      return `### ${state[0]?.toUpperCase()}${state.slice(1)} (${counts[state]})\n\n${body}`;
    })
    .join('\n\n');
  return `# Toolip baseline comparison\n\n- Baseline: \`${escapeMarkdown(delta.comparisonBase)}\`\n- Coverage comparable: **${delta.coverageComparable}**\n${delta.coverageComparable ? '' : '- Missing findings are unknown because one or both scans are incomplete. No items are reported as fixed.'}\n\n${sections}\n`;
}

function renderHtml(delta: BaselineDelta, rows: DeltaRow[]): string {
  const counts = countStates(rows);
  const sections = (['new', 'fixed', 'unchanged', 'unknown'] as const)
    .map((state) => {
      const selected = rows.filter((row) => row.state === state);
      const items = selected.length
        ? selected
            .map(
              (row) =>
                `<li><code>${escapeHtml(row.record?.ruleId ?? 'finding')}</code> <code>${escapeHtml(row.fingerprint)}</code></li>`
            )
            .join('')
        : '<li>None</li>';
      return `<section><h2>${state[0]?.toUpperCase()}${state.slice(1)} (${counts[state]})</h2><ul>${items}</ul></section>`;
    })
    .join('\n');
  const incompleteNote = delta.coverageComparable
    ? ''
    : '<p>Coverage is incomplete. Missing findings are unknown and are not reported as fixed.</p>';
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Toolip baseline comparison</title><body><main><h1>Toolip baseline comparison</h1><p>Baseline: <code>${escapeHtml(delta.comparisonBase)}</code></p><p>Coverage comparable: ${delta.coverageComparable}</p>${incompleteNote}${sections}</main></body></html>\n`;
}

function createSarif(
  delta: BaselineDelta,
  current: HistoryEntry,
  rows: DeltaRow[]
): Record<string, unknown> {
  const rules = new Map<string, Record<string, unknown>>();
  const results = rows.map((row) => {
    const ruleId = safeRuleId(row.record?.ruleId);
    rules.set(ruleId, {
      id: ruleId,
      shortDescription: { text: `History finding ${row.state}` }
    });
    const severity = row.record?.severity ?? 'medium';
    return {
      ruleId,
      level: sarifLevel(severity),
      message: {
        text: `${row.state} finding fingerprint ${row.fingerprint}`
      },
      ...(row.state === 'new'
        ? { baselineState: 'new' }
        : row.state === 'fixed'
          ? { baselineState: 'absent' }
          : row.state === 'unchanged'
            ? { baselineState: 'unchanged' }
            : {}),
      partialFingerprints: { 'toolip/v1': row.fingerprint },
      properties: {
        deltaState: row.state,
        coverageComparable: delta.coverageComparable,
        ...(row.record?.severity ? { severity: row.record.severity } : {})
      }
    };
  });
  return sanitizeOutput({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Toolip',
            semanticVersion: current.toolipVersion,
            rules: [...rules.values()].sort((left, right) =>
              String(left.id).localeCompare(String(right.id))
            )
          }
        },
        results,
        invocations: [
          {
            executionSuccessful: delta.coverageComparable,
            properties: {
              analysisState: delta.coverageComparable ? 'complete' : 'partial',
              comparisonBase: delta.comparisonBase,
              counts: countStates(rows)
            }
          }
        ]
      }
    ]
  });
}

function safeRuleId(value: string | undefined): string {
  return value && /^[A-Za-z0-9._-]{1,128}$/u.test(value)
    ? value
    : 'TOOLIP-HISTORY-001';
}

function sarifLevel(severity: FindingSeverity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/gu, (character) => {
    switch (character) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      default:
        return '&#39;';
    }
  });
}

function escapeMarkdown(value: string): string {
  return value.replaceAll('`', '\\`').replaceAll('|', '\\|');
}
