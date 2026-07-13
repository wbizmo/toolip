import type { Finding } from './finding.js';

export type AnalyzerContext = {
  root: string;
  signal?: AbortSignal;
  cache?: AnalyzerCache;
  options?: Record<string, unknown>;
};

export type AnalyzerCache = {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T, ttlMs?: number): Promise<void>;
};

export type AnalyzerResult = {
  analyzer: string;
  durationMs: number;
  findings: Finding[];
  warnings?: string[];
  metadata?: Record<string, unknown>;
};

export interface Analyzer {
  readonly id: string;
  readonly version: string;
  analyze(context: AnalyzerContext): Promise<AnalyzerResult>;
}
