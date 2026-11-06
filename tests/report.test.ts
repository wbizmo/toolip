import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/contracts/finding.js';
import { createReport } from '../src/core/report.js';
import {
  detectReportFormat,
  renderMarkdownReport
} from '../src/core/report-writer.js';

function finding(
  id: string,
  severity: Finding['severity'],
  remediation: string
): Finding {
  return {
    id,
    ruleId: id,
    title: id === 'TOOLIP-1' ? 'Example finding' : id,
    severity,
    confidence: 'high',
    category: 'test',
    message: id === 'TOOLIP-1' ? 'Something happened.' : id,
    source: 'test',
    remediation: { summary: remediation }
  };
}

describe('report', () => {
  it('summarizes canonical findings and serializes the legacy report shape', () => {
    const report = createReport({
      version: '0.1.0',
      command: 'scan',
      root: '/project',
      findings: [
        finding('A', 'critical', 'Fix A'),
        finding('B', 'medium', 'Fix B'),
        finding('C', 'info', 'Fix C')
      ]
    });

    expect(report.summary.totalFindings).toBe(3);
    expect(report.summary.critical).toBe(1);
    expect(report.summary.medium).toBe(1);
    expect(report.summary.info).toBe(1);
    expect(report.findings[0]).toMatchObject({
      id: 'A',
      recommendation: 'Fix A'
    });
    expect('ruleId' in (report.findings[0] ?? {})).toBe(false);
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
      findings: [finding('TOOLIP-1', 'low', 'Do the right thing.')]
    });

    const markdown = renderMarkdownReport(report);

    expect(markdown).toContain('# Toolip Report');
    expect(markdown).toContain('Example finding');
    expect(markdown).toContain('LOW');
    expect(markdown).toContain('Do the right thing.');
  });

  it('redacts credential-bearing message and remediation fields at report boundaries', () => {
    const credential = `ghp_${'a'.repeat(36)}`;
    const report = createReport({
      version: '0.1.0',
      command: 'scan',
      root: '/project',
      findings: [
        {
          ...finding('credential', 'high', `rotate ${credential}`),
          message: `https://user:${credential}@example.test/?token=${credential}`,
          metadata: { nested: { password: credential } },
          evidence: [
            { summary: `NPM_TOKEN=${credential}`, fingerprint: credential }
          ]
        }
      ]
    });
    expect(JSON.stringify(report)).not.toContain(credential);
    expect(JSON.stringify(report)).toContain('[redacted]');
  });

  it('sanitizes analysis reasons and nested finding metadata for the whole report', () => {
    const credential = `ghp_${'b'.repeat(36)}`;
    const report = createReport({
      version: '0.1.0',
      command: 'scan',
      root: '/project',
      findings: [
        {
          ...finding('nested', 'high', 'Rotate this credential.'),
          metadata: {
            credentials: { password: 'correct horse battery staple' }
          }
        }
      ],
      analysis: {
        state: 'partial',
        reasons: [`provider failed: ${credential}`]
      }
    });
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain(credential);
    expect(serialized).not.toContain('correct horse battery staple');
  });
});
