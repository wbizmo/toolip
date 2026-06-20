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

export async function writeReport(outputPath: string, report: ToolipReport): Promise<void> {
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
          const evidenceLine = finding.evidence ? `\n- Evidence: \`${finding.evidence}\`` : '';

          return `### ${finding.title}

- ID: \`${finding.id}\`
- Severity: **${finding.severity.toUpperCase()}**
- Category: ${finding.category}${fileLine}${evidenceLine}

${finding.message}

**Recommendation:** ${finding.recommendation}
`;
        })
        .join('\n')
    : 'No findings were detected.';

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

## Findings

${findings}
`;
}
