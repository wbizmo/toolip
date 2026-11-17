import type { ToolipReport } from './report.js';
import type { ReportEvidenceVerification } from './report-signature.js';

/**
 * A badge describes one authenticated scan result, not the security of an
 * entire project. This contract deliberately has no "zero vulnerabilities"
 * state and never treats a missing policy decision as a pass.
 */
export type ScanBadgeStatus =
  | 'policy-passing'
  | 'findings'
  | 'incomplete'
  | 'stale'
  | 'unverified'
  | 'failed';

export type ScanBadge = Readonly<{
  schema: 'toolip.dev/scan-badge/v1';
  status: ScanBadgeStatus;
  label: string;
  verified: boolean;
  scope: 'signed-report';
  revision?: string;
  projectId?: string;
  scannerArtifactSha256?: string;
  policySha256?: string;
  signedAt?: string;
  coverage: Readonly<{
    eligible: number;
    scanned: number;
    skipped: number;
    failed: number;
  }> | null;
  findings: number | null;
}>;

export type BadgePolicyDecision = Readonly<{
  decision: 'pass' | 'fail';
  policySha256: string;
  /** The policy expressly applies to this signed report's scan, not the repo in general. */
  scope: 'scan';
}>;

const labels: Record<ScanBadgeStatus, string> = {
  'policy-passing': 'policy passing (scoped)',
  findings: 'findings reported',
  incomplete: 'scan incomplete',
  stale: 'scan stale',
  unverified: 'scan unverified',
  failed: 'scan failed'
};

const safeCount = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;

function saneSummary(report: ToolipReport): boolean {
  const summary = report.summary;
  if (!summary || !Array.isArray(report.findings)) return false;
  const fields = [
    summary.critical,
    summary.high,
    summary.medium,
    summary.low,
    summary.info
  ];
  return (
    safeCount(summary.totalFindings) &&
    fields.every(safeCount) &&
    fields.reduce<number>((sum, count) => sum + count, 0) ===
      summary.totalFindings &&
    report.findings.length === summary.totalFindings
  );
}

function saneCoverage(report: ToolipReport): boolean {
  const analysis = report.analysis;
  const coverage = analysis?.coverage;
  return (
    analysis?.state === 'complete' &&
    Array.isArray(analysis.reasons) &&
    analysis.reasons.length === 0 &&
    coverage?.state === 'complete' &&
    safeCount(coverage.eligible) &&
    safeCount(coverage.scanned) &&
    safeCount(coverage.skipped) &&
    safeCount(coverage.failed) &&
    coverage.scanned === coverage.eligible &&
    coverage.skipped === 0 &&
    coverage.failed === 0 &&
    (!report.analyzerPlugins ||
      report.analyzerPlugins.every((plugin) => plugin.state === 'complete'))
  );
}

/**
 * Computes a static badge only from an already verified report. When the
 * caller has not bound the signature to an expected immutable revision, the
 * badge MUST remain unverified even if its cryptographic signature is valid.
 */
export function createScanBadge(
  report: ToolipReport,
  verification: ReportEvidenceVerification,
  input: { expectedRevision?: string } = {}
): ScanBadge {
  const signature = report.evidenceSignature;
  const subject = signature?.subject;
  const revision = subject?.gitRevision;
  const matchingRevision =
    typeof input.expectedRevision === 'string' &&
    /^[a-f0-9]{40}$/u.test(input.expectedRevision) &&
    revision === input.expectedRevision;
  const verified = verification.status === 'verified' && matchingRevision;
  const coverage = report.analysis?.coverage;
  const summaryValid = saneSummary(report);
  const isComplete = saneCoverage(report);
  const policy = (report as ToolipReport & { badgePolicy?: BadgePolicyDecision })
    .badgePolicy;
  const policySha256 =
    policy &&
    (policy.decision === 'pass' || policy.decision === 'fail') &&
    policy.scope === 'scan' &&
    /^[a-f0-9]{64}$/u.test(policy.policySha256)
      ? policy.policySha256
      : undefined;
  const policyPass = policy?.decision === 'pass' && policySha256 !== undefined;

  let status: ScanBadgeStatus;
  if (!summaryValid || verification.status === 'invalid') {
    status = 'failed';
  } else if (verification.status === 'expired') {
    status = 'stale';
  } else if (report.analysis?.state === 'failed') {
    status = 'failed';
  } else if (!isComplete) {
    status = 'incomplete';
  } else if (!verified) {
    status = 'unverified';
  } else if (report.summary.totalFindings > 0 || policy?.decision === 'fail') {
    status = 'findings';
  } else if (policyPass) {
    status = 'policy-passing';
  } else {
    // An authenticated, complete scan is not evidence that a policy passed.
    status = 'unverified';
  }
  return Object.freeze({
    schema: 'toolip.dev/scan-badge/v1',
    status,
    label: labels[status],
    verified,
    scope: 'signed-report',
    ...(verified && revision ? { revision } : {}),
    ...(verified && signature
      ? {
          projectId: verification.status === 'verified' ? verification.projectId : undefined,
          scannerArtifactSha256: signature.scannerArtifactSha256,
          signedAt: signature.issuedAt
        }
      : {}),
    ...(verified && policySha256 ? { policySha256 } : {}),
    coverage:
      coverage &&
      safeCount(coverage.eligible) &&
      safeCount(coverage.scanned) &&
      safeCount(coverage.skipped) &&
      safeCount(coverage.failed)
        ? Object.freeze({
            eligible: coverage.eligible,
            scanned: coverage.scanned,
            skipped: coverage.skipped,
            failed: coverage.failed
          })
        : null,
    findings: summaryValid ? report.summary.totalFindings : null
  });
}

const appearance: Record<ScanBadgeStatus, Readonly<{ text: string; fill: string }>> = {
  'policy-passing': { text: 'policy passing (scoped)', fill: '#286d43' },
  findings: { text: 'findings', fill: '#a04b16' },
  incomplete: { text: 'incomplete', fill: '#735b1e' },
  stale: { text: 'stale', fill: '#6b6477' },
  unverified: { text: 'unverified', fill: '#586373' },
  failed: { text: 'failed', fill: '#a12f35' }
};

/** No untrusted values enter the SVG; all strings are fixed constants. */
export function renderScanBadgeSvg(badge: ScanBadge): string {
  const current = appearance[badge.status];
  if (!current) throw new TypeError('Unknown Toolip badge state.');
  const title = `Toolip: ${current.text}`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="230" height="20" role="img" aria-label="${title}"><title>${title}</title><rect width="78" height="20" fill="#343a40"/><rect x="78" width="152" height="20" fill="${current.fill}"/><g fill="#fff" font-family="DejaVu Sans,Verdana,sans-serif" font-size="11" text-anchor="middle"><text x="39" y="14">Toolip</text><text x="154" y="14">${current.text}</text></g></svg>\n`;
}
