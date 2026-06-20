export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type ToolipFinding = {
  id: string;
  title: string;
  severity: FindingSeverity;
  category: string;
  message: string;
  recommendation: string;
  file?: string;
  evidence?: string;
};

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
  findings: ToolipFinding[];
};

export function createReport(input: {
  version: string;
  command: string;
  root: string;
  findings: ToolipFinding[];
}): ToolipReport {
  return {
    tool: 'toolip',
    version: input.version,
    command: input.command,
    generatedAt: new Date().toISOString(),
    root: input.root,
    summary: summarizeFindings(input.findings),
    findings: input.findings
  };
}

export function summarizeFindings(findings: ToolipFinding[]): ToolipReport['summary'] {
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
