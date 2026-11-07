import type { AnalysisCoverage } from '../../contracts/analysis.js';
import type { FindingSeverity } from '../../contracts/finding.js';

export type HistorySummary = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
};

export type HistoryEntry = {
  id: string;
  createdAt: string;
  toolipVersion: string;
  command: string;
  git?: {
    branch?: string;
    commit?: string;
    dirty?: boolean;
  };
  score?: number;
  summary: HistorySummary;
  findingIds: string[];
  /** Stable identities omit source line numbers so line movement is not a new risk. */
  findingFingerprints?: string[];
  findingRecords?: HistoryFindingRecord[];
  coverage?: AnalysisCoverage;
  metadata?: Record<string, unknown>;
};

export type HistoryFindingRecord = {
  fingerprint: string;
  ruleId: string;
  severity: FindingSeverity;
  firstSeenAt: string;
};

export type HistoryStore = {
  schemaVersion: '1.0';
  entries: HistoryEntry[];
};
