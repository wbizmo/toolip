import { describe, expect, it } from 'vitest';
import { createReport } from '../../src/core/report.js';
import { toGitLabSastReport } from '../../src/integrations/gitlab/report.js';
import type { Finding } from '../../src/contracts/finding.js';

const located: Finding = {
  id: 'TLP-SAST-101',
  ruleId: 'TLP-SAST-101',
  title: 'Unsafe path use',
  category: 'path',
  severity: 'high',
  confidence: 'high',
  message: 'A user-controlled path reaches a sensitive operation.',
  source: 'ast',
  location: { file: 'src/handler.ts', line: 14, endLine: 16 }
};

describe('GitLab SAST conversion', () => {
  it('preserves safe source coordinates and report completeness', () => {
    const report = createReport({
      version: '3.2.1',
      command: 'scan',
      root: '/redacted/repo',
      findings: [located],
      analysis: {
        state: 'complete',
        reasons: [],
        coverage: { state: 'complete', eligible: 1, scanned: 1, skipped: 0, failed: 0 }
      }
    });
    const result = toGitLabSastReport(report);
    expect(result.scan.status).toBe('success');
    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.vulnerabilities[0]?.location).toEqual({
      file: 'src/handler.ts', start_line: 14, end_line: 16
    });
    expect(result.vulnerabilities[0]?.severity).toBe('High');
    expect(JSON.stringify(result)).not.toContain('/redacted/repo');
  });

  it('never fabricates coordinates for unlocated or unsafe-path findings', () => {
    const report = createReport({
      version: '3.2.1',
      command: 'scan',
      root: '/private/repo',
      findings: [
        { ...located, location: undefined },
        { ...located, id: 'x', location: { file: '../outside.ts', line: 1 } },
        located
      ],
      analysis: { state: 'complete', reasons: [] }
    });
    const result = toGitLabSastReport(report);
    expect(result.scan.status).toBe('failure');
    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.toolip.unmappedFindings).toBe(2);
  });

  it('keeps partial scans failed despite an empty vulnerability array', () => {
    const report = createReport({
      version: '3.2.1',
      command: 'scan',
      root: '/private/repo',
      findings: [],
      analysis: {
        state: 'partial',
        reasons: ['one file unreadable'],
        coverage: { state: 'partial', eligible: 1, scanned: 0, skipped: 1, failed: 0 }
      }
    });
    const result = toGitLabSastReport(report);
    expect(result.scan.status).toBe('failure');
    expect(result.toolip.incomplete).toBe(true);
    expect(result.vulnerabilities).toEqual([]);
  });
});
