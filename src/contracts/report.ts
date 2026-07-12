import type { Finding } from './finding.js';

export const TOOLIP_REPORT_SCHEMA_VERSION = '2.0';

export type ReportSummary = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
};

export type ToolipReportV2 = {
  schemaVersion: typeof TOOLIP_REPORT_SCHEMA_VERSION;
  generatedAt: string;
  toolipVersion: string;
  project: {
    root: string;
    name?: string;
    packageManager?: string;
  };
  summary: ReportSummary;
  findings: Finding[];
  analyzers: Array<{
    id: string;
    version: string;
    durationMs: number;
    findingCount: number;
    warnings?: string[];
  }>;
  metadata?: Record<string, unknown>;
};
