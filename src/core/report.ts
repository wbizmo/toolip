import type {
  Finding,
  FindingSeverity
} from '../contracts/finding.js';

export type SerializedFinding = {
  id: string;
  title: string;
  severity: FindingSeverity;
  category: string;
  message: string;
  recommendation: string;
  file?: string;
  evidence?: string;
};

/** @deprecated Use Finding internally. This alias exists only for report-shape compatibility. */
export type ToolipFinding = SerializedFinding;

export type ToolipReport = {
  tool: 'toolip';
  version: string;
  command: string;
  generatedAt: string;
  root: string;
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: SerializedFinding[];
};

export function serializeFinding(
  finding: Finding
): SerializedFinding {
  return {
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    category: finding.category,
    message: finding.message,
    recommendation:
      finding.remediation?.summary ??
      'Review this finding and apply an appropriate mitigation.',
    file: finding.location?.file,
    evidence: finding.evidence?.[0]?.summary
  };
}

export function createReport(input: {
  version: string;
  command: string;
  root: string;
  findings: Finding[];
}): ToolipReport {
  return {
    tool: 'toolip',
    version: input.version,
    command: input.command,
    generatedAt: new Date().toISOString(),
    root: input.root,
    summary: summarizeFindings(input.findings),
    findings: input.findings.map(serializeFinding)
  };
}

export function summarizeFindings(
  findings: Pick<Finding, 'severity'>[]
): ToolipReport['summary'] {
  return findings.reduce<ToolipReport['summary']>(
    (summary, finding) => {
      summary.totalFindings += 1;
      summary[finding.severity] += 1;
      return summary;
    },
    {
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    }
  );
}
