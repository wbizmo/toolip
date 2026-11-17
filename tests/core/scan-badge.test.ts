import { describe, expect, it } from 'vitest';
import type { ToolipReport } from '../../src/core/report.js';
import type { ReportEvidenceVerification } from '../../src/core/report-signature.js';
import {
  createScanBadge,
  renderScanBadgeSvg
} from '../../src/core/scan-badge.js';

const revision = 'a'.repeat(40);
const verified: ReportEvidenceVerification = {
  status: 'verified',
  payloadSha256: 'a'.repeat(64),
  scannerArtifactSha256: 'b'.repeat(64),
  keyId: 'reviewed-signing-key',
  projectId: 'org/repository'
};
function report(
  options: {
    state?: 'complete' | 'partial' | 'failed';
    findings?: number;
    revision?: string;
    policy?: 'pass' | 'fail';
  } = {}
): ToolipReport {
  const state = options.state ?? 'complete';
  const findings = options.findings ?? 0;
  return {
    tool: 'toolip',
    version: '3.2.1',
    command: 'scan',
    generatedAt: '2026-11-17T00:00:00.000Z',
    root: '/private/project',
    summary: {
      totalFindings: findings,
      critical: findings,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    findings: Array.from({ length: findings }, (_, index) => ({
      id: `TLP-${index}`,
      title: 'Risk',
      severity: 'critical',
      category: 'test',
      message: 'No source excerpt',
      recommendation: 'Review'
    })),
    analysis: {
      state,
      reasons: state === 'complete' ? [] : ['unexamined inputs'],
      coverage: {
        state,
        eligible: 1,
        scanned: state === 'complete' ? 1 : 0,
        skipped: state === 'complete' ? 0 : 1,
        failed: 0
      }
    },
    evidenceSignature: {
      schema: 'toolip.dev/evidence/v2',
      algorithm: 'Ed25519',
      keyId: 'reviewed-signing-key',
      projectId: 'org/repository',
      issuedAt: '2026-11-17T00:00:00.000Z',
      scannerArtifactSha256: 'b'.repeat(64),
      subject: { gitRevision: options.revision ?? revision },
      payloadSha256: 'a'.repeat(64),
      signature: 'placeholder-signature'
    },
    ...(options.policy
      ? {
          badgePolicy: {
            decision: options.policy,
            policySha256: 'f'.repeat(64),
            scope: 'scan'
          }
        }
      : {})
  };
}

describe('signed scan badge safety contract', () => {
  it('cannot call a no-findings scan policy passing without an attested policy decision', () => {
    const badge = createScanBadge(report(), verified, {
      expectedRevision: revision
    });
    expect(badge.status).toBe('unverified');
    expect(badge.verified).toBe(true);
    expect(badge.policySha256).toBeUndefined();
  });

  it('requires exact source revision and verified evidence before a scoped policy pass', () => {
    const signed = report({ policy: 'pass' });
    expect(createScanBadge(signed, verified, { expectedRevision: revision }).status)
      .toBe('policy-passing');
    expect(createScanBadge(signed, verified, { expectedRevision: 'c'.repeat(40) }).status)
      .toBe('unverified');
    expect(createScanBadge(signed, { status: 'unsigned', reason: 'signature-missing' }, {
      expectedRevision: revision
    }).status).toBe('unverified');
  });

  it('reports actual findings or a failed policy instead of claiming success', () => {
    expect(createScanBadge(report({ findings: 1, policy: 'pass' }), verified, {
      expectedRevision: revision
    }).status).toBe('findings');
    expect(createScanBadge(report({ policy: 'fail' }), verified, {
      expectedRevision: revision
    }).status).toBe('findings');
  });

  it('does not turn partial, stale, invalid or malformed reports green', () => {
    expect(createScanBadge(report({ state: 'partial', policy: 'pass' }), verified, {
      expectedRevision: revision
    }).status).toBe('incomplete');
    expect(createScanBadge(report({ policy: 'pass' }), {
      status: 'expired',
      reason: 'signature-expired'
    }, { expectedRevision: revision }).status).toBe('stale');
    expect(createScanBadge(report({ policy: 'pass' }), {
      status: 'invalid',
      reason: 'signature-invalid'
    }, { expectedRevision: revision }).status).toBe('failed');
    const malformed = report({ policy: 'pass' });
    malformed.summary.totalFindings = 12;
    expect(createScanBadge(malformed, verified, {
      expectedRevision: revision
    }).status).toBe('failed');
  });

  it('renders only fixed trusted strings in SVG, never report or badge metadata', () => {
    const badge = {
      ...createScanBadge(report({ policy: 'pass' }), verified, {
        expectedRevision: revision
      }),
      label: '<script>alert(1)</script>',
      projectId: '<image href="https://evil.example/file">'
    };
    const svg = renderScanBadgeSvg(badge);
    expect(svg).toContain('Toolip');
    expect(svg).toContain('policy passing (scoped)');
    expect(svg).not.toContain('<script>');
    expect(svg).not.toContain('<image');
    expect(svg).not.toContain('https://');
  });
});
