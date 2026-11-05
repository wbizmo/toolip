import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { ToolipReport } from './report.js';

export type ReportFormat = 'json' | 'md';

export function detectReportFormat(outputPath: string): ReportFormat {
  const extension = path.extname(outputPath).toLowerCase();

  if (extension === '.md' || extension === '.markdown') {
    return 'md';
  }

  return 'json';
}

export async function writeReport(
  outputPath: string,
  report: ToolipReport
): Promise<void> {
  const format = detectReportFormat(outputPath);

  if (format === 'md') {
    await writeFile(outputPath, renderMarkdownReport(report), 'utf8');
    return;
  }

  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
}

export function renderMarkdownReport(report: ToolipReport): string {
  const findings = report.findings.length
    ? report.findings
        .map((finding) => {
          const fileLine = finding.file ? `\n- File: \`${finding.file}\`` : '';
          const evidenceLine = finding.evidence
            ? `\n- Evidence: \`${finding.evidence}\``
            : '';

          return `### ${finding.title}

- ID: \`${finding.id}\`
- Severity: **${finding.severity.toUpperCase()}**
- Category: ${finding.category}${fileLine}${evidenceLine}

${finding.message}

**Recommendation:** ${finding.recommendation}
`;
        })
        .join('\n')
    : report.analysis && report.analysis.state !== 'complete'
      ? `No findings were reported, but the analysis was **${report.analysis.state.toUpperCase()}**, so this is not an all-clear.`
      : 'No findings were detected.';

  const coverage = report.analysis?.coverage;
  const coverageSection = coverage
    ? `\n- Eligible: ${coverage.eligible}\n- Scanned: ${coverage.scanned}\n- Skipped: ${coverage.skipped}\n- Failed: ${coverage.failed}\n- Excluded: ${coverage.excluded ?? 0}`
    : '';
  const analysisSection = report.analysis
    ? `\n## Analysis\n\n- State: **${report.analysis.state.toUpperCase()}**${report.analysis.reasons.map((reason) => `\n- ${reason}`).join('')}${coverageSection}\n`
    : '';

  return `# Toolip Report

Generated: ${report.generatedAt}

Root: \`${report.root}\`

Command: \`${report.command}\`

## Summary

| Severity | Count |
|---|---:|
| Critical | ${report.summary.critical} |
| High | ${report.summary.high} |
| Medium | ${report.summary.medium} |
| Low | ${report.summary.low} |
| Info | ${report.summary.info} |
| Total | ${report.summary.totalFindings} |
${analysisSection}
## Findings

${findings}
`;
}
