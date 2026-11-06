import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/contracts/finding.js';
import { createReport, serializeFinding } from '../src/core/report.js';
import { renderHtmlReport } from '../src/core/publish/html.js';
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

  it('redacts unquoted passphrase and passwd fields in serialized and markdown reports', () => {
    const report = createReport({
      version: '0.1.0',
      command: 'scan',
      root: '/project',
      findings: [
        {
          ...finding(
            'TLP-SECRET-PASSWORD:config.ts:10:2',
            'high',
            'Rotate it.'
          ),
          message:
            'unlock failed: passphrase=first-secret passwd=second-secret',
          location: { file: 'config.ts', line: 10, column: 2 }
        },
        {
          ...finding(
            'TLP-SECRET-PASSWORD:config.ts:11:2',
            'high',
            'Rotate it.'
          ),
          message:
            'unlock failed: passphrase=third-secret passwd=fourth-secret',
          location: { file: 'config.ts', line: 11, column: 2 }
        }
      ]
    });
    const serialized = JSON.stringify(report);
    const markdown = renderMarkdownReport(report);

    expect(serialized).toContain('passphrase=[redacted]');
    expect(serialized).toContain('passwd=[redacted]');
    for (const secret of [
      'first-secret',
      'second-secret',
      'third-secret',
      'fourth-secret'
    ]) {
      expect(serialized).not.toContain(secret);
      expect(markdown).not.toContain(secret);
    }
    expect(report.findings[0]?.id).not.toBe(report.findings[1]?.id);
  });

  it('redacts non-HTTP URL userinfo in serialized and markdown reports', () => {
    const report = createReport({
      version: '0.1.0',
      command: 'scan',
      root: '/project',
      findings: [
        {
          ...finding(
            'provider-error',
            'high',
            'Retry with a fresh credential.'
          ),
          message:
            'git provider failed for git+ssh://alice:provider-secret@git.example/org/repo'
        }
      ]
    });
    const serialized = JSON.stringify(report);
    const markdown = renderMarkdownReport(report);

    expect(serialized).toContain('git+ssh://[redacted]@git.example/org/repo');
    expect(markdown).toContain('git+ssh://[redacted]@git.example/org/repo');
    expect(serialized).not.toContain('provider-secret');
    expect(markdown).not.toContain('provider-secret');
  });

  it('redacts credentials from serialized findings rendered as HTML', () => {
    const credential = `ghp_${'d'.repeat(36)}`;
    const serialized = serializeFinding(
      finding('credential', 'high', `rotate ${credential}`)
    );
    const html = renderHtmlReport({
      project: '/project',
      generatedAt: '2026-01-01T00:00:00.000Z',
      findings: [serialized]
    });

    expect(html).not.toContain(credential);
    expect(html).toContain('rotate [redacted-token]');
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
