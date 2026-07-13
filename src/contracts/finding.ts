export const findingSeverities = [
  'critical',
  'high',
  'medium',
  'low',
  'info'
] as const;

export type FindingSeverity = (typeof findingSeverities)[number];

export const findingConfidences = [
  'high',
  'medium',
  'low'
] as const;

export type FindingConfidence = (typeof findingConfidences)[number];

export type FindingLocation = {
  file: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
};

export type FindingEvidence = {
  summary: string;
  excerpt?: string;
  fingerprint?: string;
};

export type FindingRemediation = {
  summary: string;
  fixedVersion?: string;
  references?: string[];
};

export type Finding = {
  id: string;
  ruleId: string;
  title: string;
  category: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  message: string;
  source: string;
  location?: FindingLocation;
  evidence?: FindingEvidence[];
  remediation?: FindingRemediation;
  metadata?: Record<string, unknown>;
};
