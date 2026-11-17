import { describe, expect, it } from 'vitest';
import { createReport } from '../../src/core/report.js';
import {
  toAzureLoggingCommands,
  toBitbucketAnnotations
} from '../../src/integrations/ci/annotations.js';
import type { Finding } from '../../src/contracts/finding.js';

const finding: Finding = {
  id: 'TLP-001',
  ruleId: 'TLP-001',
  title: 'SQL injection attempt',
  category: 'injection',
  severity: 'high',
  confidence: 'medium',
  message: 'Potential untrusted SQL input.',
  source: 'ast',
  location: { file: 'src/a.ts', line: 12 }
};

describe('Azure and Bitbucket report adaptation', () => {
  it('escapes Azure control characters and prevents logging-command injection', () => {
    const report = createReport({
      version: '3.2.1', command: 'scan', root: '/private/repo',
      findings: [{
        ...finding,
        title: 'Warning ]\n##vso[task.setvariable variable=secret]bad',
        location: { file: 'src/name];x.ts', line: 15 }
      }],
      analysis: {
        state: 'complete', reasons: [],
        coverage: { state: 'complete', eligible: 1, scanned: 1, skipped: 0, failed: 0 }
      }
    });
    const lines = toAzureLoggingCommands(report);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('%5D');
    expect(lines[0]).not.toContain('\n##vso[');
    expect(lines[0]).not.toContain('/private/repo');
  });

  it('rejects false clean when Toolip report is incomplete', () => {
    const report = createReport({
      version: '3.2.1', command: 'scan', root: '/private/repo', findings: [],
      analysis: {
        state: 'partial', reasons: ['unreadable file'],
        coverage: { state: 'partial', eligible: 1, scanned: 0, skipped: 1, failed: 0 }
      }
    });
    expect(toAzureLoggingCommands(report).join('\n')).toContain('TOOLIP_INCOMPLETE');
    expect(toBitbucketAnnotations(report).result).toBe('incomplete');
  });

  it('preserves exact source lines and leaves unlocated findings explicitly unmapped', () => {
    const report = createReport({
      version: '3.2.1', command: 'scan', root: '/private/repo',
      findings: [finding, { ...finding, id: 'TLP-002', location: undefined }],
      analysis: { state: 'complete', reasons: [] }
    });
    const converted = toBitbucketAnnotations(report);
    expect(converted.result).toBe('incomplete');
    expect(converted.mappedFindings).toBe(1);
    expect(converted.unmappedFindings).toBe(1);
    expect(converted.annotations[0]).toMatchObject({
      path: 'src/a.ts', line: 12, annotation_type: 'VULNERABILITY'
    });
  });
});
