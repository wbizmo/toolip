import { describe, expect, it } from 'vitest';
import { createReport } from '../src/core/report.js';
import { detectReportFormat, renderMarkdownReport } from '../src/core/report-writer.js';

describe('report', () => {
  it('summarizes findings by severity', () => {
    const report = createReport({
      version: '0.1.0',
      command: 'scan',
      root: '/project',
      findings: [
        {
          id: 'A',
          title: 'A',
          severity: 'critical',
          category: 'test',
          message: 'A',
          recommendation: 'Fix A'
        },
        {
          id: 'B',
          title: 'B',
          severity: 'medium',
          category: 'test',
          message: 'B',
          recommendation: 'Fix B'
        },
        {
          id: 'C',
          title: 'C',
          severity: 'info',
          category: 'test',
          message: 'C',
          recommendation: 'Fix C'
        }
      ]
    });

    expect(report.summary.totalFindings).toBe(3);
    expect(report.summary.critical).toBe(1);
    expect(report.summary.medium).toBe(1);
    expect(report.summary.info).toBe(1);
  });

  it('detects report formats', () => {
    expect(detectReportFormat('report.json')).toBe('json');
    expect(detectReportFormat('report.md')).toBe('md');
    expect(detectReportFormat('report.markdown')).toBe('md');
  });

  it('renders markdown reports', () => {
    const report = createReport({
      version: '0.1.0',
      command: 'doctor',
      root: '/project',
      findings: [
        {
          id: 'TOOLIP-1',
          title: 'Example finding',
          severity: 'low',
          category: 'test',
          message: 'Something happened.',
          recommendation: 'Do the right thing.'
        }
      ]
    });

    const markdown = renderMarkdownReport(report);

    expect(markdown).toContain('# Toolip Report');
    expect(markdown).toContain('Example finding');
    expect(markdown).toContain('LOW');
  });
});
