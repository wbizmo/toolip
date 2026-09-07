import { runGitAudit } from './git-audit.js';
import { createScannerContext } from './scanner-context.js';
import { runSecurityDoctor } from './security-doctor.js';
import type { ToolipFinding } from './report.js';

export type PreCommitResult = {
  passed: boolean;
  findings: ToolipFinding[];
  summary: {
    critical: number;
    high: number;
    blocking: number;
  };
};

export async function runPreCommit(root: string): Promise<PreCommitResult> {
  const context = await createScannerContext(root);
  const [doctor, gitAudit] = await Promise.all([
    runSecurityDoctor(context),
    runGitAudit(context)
  ]);

  const findings = [...doctor.findings, ...gitAudit.findings];
  const critical = findings.filter((finding) => finding.severity === 'critical').length;
  const high = findings.filter((finding) => finding.severity === 'high').length;
  const blocking = critical + high;

  return {
    passed: blocking === 0,
    findings,
    summary: {
      critical,
      high,
      blocking
    }
  };
}
