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
  metadata?: Record<string, unknown>;
};

export type HistoryStore = {
  schemaVersion: '1.0';
  entries: HistoryEntry[];
};
