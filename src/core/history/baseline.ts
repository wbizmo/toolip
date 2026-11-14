import { createHash } from 'node:crypto';
import path from 'node:path';
import type { Finding } from '../../contracts/finding.js';
import type { HistoryEntry, HistoryFindingRecord } from './types.js';

const stableMetadataKeys = [
  'ecosystem',
  'package',
  'installedVersion',
  'version',
  'installPath',
  'vulnerabilityId',
  'lifecycle',
  'nodeKind',
  'ruleVersion',
  'resourceType',
  'resourceName',
  'stage',
  'setting'
] as const;

/** Generates a privacy-safe finding identity that is independent of line numbers. */
export function findingFingerprint(finding: Finding, root: string): string {
  const metadata = finding.metadata ?? {};
  const file = finding.location?.file
    ? stablePath(finding.location.file, root)
    : undefined;
  const identity: Record<string, unknown> = {
    ruleId: finding.ruleId,
    category: finding.category,
    source: finding.source,
    file,
    title: finding.title,
    metadata: Object.fromEntries(
      stableMetadataKeys.flatMap((key) =>
        typeof metadata[key] === 'string' ||
        typeof metadata[key] === 'number' ||
        typeof metadata[key] === 'boolean'
          ? [[key, metadata[key]]]
          : []
      )
    )
  };
  // Secret values and process-keyed secret fingerprints must never enter local
  // history. A source column differentiates common same-line occurrences.
  if (finding.category === 'secrets' && finding.location?.column !== undefined)
    identity.column = finding.location.column;
  const canonical = JSON.stringify(identity);
  return createHash('sha256').update(canonical).digest('hex');
}

/** Builds stable history records and preserves the first observed time for findings still present. */
export function historyFindingRecords(input: {
  findings: Finding[];
  root: string;
  createdAt: string;
  previous?: HistoryEntry;
}): HistoryFindingRecord[] {
  const firstSeen = new Map(
    (input.previous?.findingRecords ?? []).map((record) => [
      record.fingerprint,
      record.firstSeenAt
    ])
  );
  const byFingerprint = new Map<string, HistoryFindingRecord>();
  for (const finding of input.findings) {
    const fingerprint = findingFingerprint(finding, input.root);
    const current = byFingerprint.get(fingerprint);
    if (
      !current ||
      severityRank(finding.severity) > severityRank(current.severity)
    ) {
      byFingerprint.set(fingerprint, {
        fingerprint,
        ruleId: finding.ruleId,
        severity: finding.severity,
        firstSeenAt: firstSeen.get(fingerprint) ?? input.createdAt
      });
    }
  }
  return [...byFingerprint.values()].sort((left, right) =>
    left.fingerprint.localeCompare(right.fingerprint)
  );
}

export type BaselineDelta = {
  new: string[];
  fixed: string[];
  unchanged: string[];
  unknown: string[];
  comparisonBase: string;
  coverageComparable: boolean;
};

/** Incomplete comparisons never claim a finding was fixed. */
export function compareHistoryEntries(
  current: HistoryEntry,
  baseline: HistoryEntry
): BaselineDelta {
  const currentIds = new Set(current.findingFingerprints ?? []);
  const baselineIds = new Set(baseline.findingFingerprints ?? []);
  const unchanged = [...currentIds]
    .filter((fingerprint) => baselineIds.has(fingerprint))
    .sort();
  const currentOnly = [...currentIds]
    .filter((fingerprint) => !baselineIds.has(fingerprint))
    .sort();
  const baselineOnly = [...baselineIds]
    .filter((fingerprint) => !currentIds.has(fingerprint))
    .sort();
  const coverageComparable =
    current.coverage?.state === 'complete' &&
    baseline.coverage?.state === 'complete' &&
    current.findingFingerprints !== undefined &&
    baseline.findingFingerprints !== undefined;
  return {
    new: coverageComparable ? currentOnly : [],
    fixed: coverageComparable ? baselineOnly : [],
    unchanged,
    unknown: coverageComparable
      ? []
      : [...new Set([...currentOnly, ...baselineOnly])].sort(),
    comparisonBase: baseline.id,
    coverageComparable
  };
}

/** Computes configurable due dates and overdue status without changing findings. */
export function remediationSla(
  entry: HistoryEntry,
  policy: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>,
  now = new Date()
): Array<HistoryFindingRecord & { dueAt: string; overdue: boolean }> {
  for (const days of Object.values(policy)) {
    if (!Number.isFinite(days) || days < 0 || days > 3650) {
      throw new RangeError('SLA values must be between 0 and 3,650 days.');
    }
  }
  return (entry.findingRecords ?? [])
    .map((record) => {
      const days = policy[record.severity];
      const firstSeen = Date.parse(record.firstSeenAt);
      if (!Number.isFinite(firstSeen))
        throw new Error('History contains an invalid first-seen timestamp.');
      const dueAt = new Date(firstSeen + days * 86_400_000);
      return {
        ...record,
        dueAt: dueAt.toISOString(),
        overdue: now.getTime() > dueAt.getTime()
      };
    })
    .sort(
      (left, right) =>
        Number(right.overdue) - Number(left.overdue) ||
        left.dueAt.localeCompare(right.dueAt) ||
        left.fingerprint.localeCompare(right.fingerprint)
    );
}

function stablePath(file: string, root: string): string {
  const absolute = path.isAbsolute(file) ? file : path.resolve(root, file);
  const relative = path.relative(path.resolve(root), path.resolve(absolute));
  return relative.split(path.sep).join('/');
}

function severityRank(severity: Finding['severity']): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity];
}
