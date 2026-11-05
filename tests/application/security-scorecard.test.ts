import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Analyzer } from '../../src/contracts/analyzer.js';
import type { Finding } from '../../src/contracts/finding.js';
import { buildSecurityScorecard } from '../../src/application/security-scorecard.js';
import { createReport } from '../../src/core/report.js';
import { renderMarkdownReport } from '../../src/core/report-writer.js';

const cleanSummary = {
  totalDependencies: 1,
  outdated: 0,
  deprecated: 0,
  highRisk: 0,
  mediumRisk: 0,
  lowRisk: 0,
  averageRiskScore: 0
};

const packageHealth = {
  name: 'example',
  installedVersion: '1.0.0',
  latestVersion: '1.0.0',
  outdated: false,
  deprecated: false,
  maintainers: 2,
  publishedAt: null,
  ageInDays: 1,
  downloads: null,
  riskScore: 0
};

function vulnerability(): Finding {
  return {
    id: 'TLP-CVE-TEST',
    ruleId: 'TLP-CVE-001',
    title: 'Known vulnerability',
    severity: 'critical',
    confidence: 'high',
    category: 'vulnerability',
    message: 'Known vulnerability',
    source: 'test',
    remediation: { summary: 'Upgrade' }
  };
}

async function fixture(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-scorecard-'));
  await writeFile(path.join(root, 'package.json'), '{}');
  return root;
}

const cleanDoctor = async () => ({
  findings: [] as Finding[],
  summary: {
    filesDiscovered: 1,
    filesEligible: 1,
    filesScanned: 1,
    filesSkipped: 0,
    readFailures: 0,
    bytesScanned: 2,
    secrets: 0,
    dangerousCode: 0,
    configuration: 0,
    headers: 0
  }
});

const cleanGit = async () => ({
  findings: [] as Finding[],
  summary: {
    filesChecked: 1,
    dangerousFiles: 0,
    gitignorePresent: true,
    envIgnored: true,
    pemIgnored: true
  }
});

describe('buildSecurityScorecard', () => {
  it('backs dependency health with an actual vulnerability result', async () => {
    const root = await fixture();
    const analyzer: Analyzer = {
      id: 'test-vulns',
      version: '1',
      analyze: async () => ({
        analyzer: 'test-vulns',
        durationMs: 0,
        findings: [vulnerability()]
      })
    };

    try {
      const result = await buildSecurityScorecard(root, {
        dependencyScan: async () => ({
          packages: [packageHealth],
          findings: [],
          summary: cleanSummary
        }),
        doctor: cleanDoctor as never,
        gitAudit: cleanGit as never,
        vulnerabilityAnalyzer: analyzer
      });

      expect(result.dependencyHealth?.vulnerabilityPenalty).toBe(40);
      expect(result.score.dependencyHealth).toBe(60);
      expect(result.score.complete).toBe(true);
      expect(result.score.overall).toBe(90);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('cannot silently improve the score when vulnerability analysis fails', async () => {
    const root = await fixture();
    const analyzer: Analyzer = {
      id: 'test-vulns',
      version: '1',
      analyze: async () => {
        throw new Error('OSV unavailable');
      }
    };

    try {
      const result = await buildSecurityScorecard(root, {
        dependencyScan: async () => ({
          packages: [packageHealth],
          findings: [],
          summary: cleanSummary
        }),
        doctor: cleanDoctor as never,
        gitAudit: cleanGit as never,
        vulnerabilityAnalyzer: analyzer
      });

      expect(result.score.dimensions.dependencyHealth.status).toBe('failed');
      expect(result.score.dependencyHealth).toBeNull();
      expect(result.score.overall).toBeNull();
      expect(result.score.grade).toBeNull();
      expect(result.score.complete).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps completed OSV findings when registry coverage is partial', async () => {
    const root = await fixture();
    const analyzer: Analyzer = {
      id: 'test-vulns',
      version: '1',
      analyze: async () => ({
        analyzer: 'test-vulns',
        durationMs: 0,
        findings: [vulnerability()],
        warnings: ['osv note']
      })
    };

    try {
      const result = await buildSecurityScorecard(root, {
        dependencyScan: async () => ({
          packages: [packageHealth],
          findings: [],
          summary: cleanSummary,
          failures: [
            {
              name: 'left',
              version: '1.0.0',
              kind: 'timed_out',
              message: 'registry timeout'
            }
          ],
          coverage: {
            state: 'partial',
            reason: '1 of 1 lookups failed',
            eligible: 1,
            scanned: 0,
            skipped: 0,
            failed: 1
          }
        }),
        doctor: cleanDoctor as never,
        gitAudit: cleanGit as never,
        vulnerabilityAnalyzer: analyzer
      });

      expect(result.score.dimensions.dependencyHealth.status).not.toBe(
        'measured'
      );
      expect(result.findings.map((f) => f.id)).toContain(vulnerability().id);
      expect(result.warnings).toContain('osv note');
      expect(result.warnings.filter((w) => w === 'osv note')).toHaveLength(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('names a failed OSV run in the reason when registry coverage is also partial', async () => {
    const root = await fixture();
    try {
      const result = await buildSecurityScorecard(root, {
        dependencyScan: async () => ({
          packages: [packageHealth],
          findings: [],
          summary: cleanSummary,
          failures: [
            {
              name: 'left',
              version: '1.0.0',
              kind: 'failed',
              message: 'registry down'
            }
          ],
          coverage: {
            state: 'partial',
            reason: '1 of 1 lookups failed',
            eligible: 1,
            scanned: 0,
            skipped: 0,
            failed: 1
          }
        }),
        doctor: cleanDoctor as never,
        gitAudit: cleanGit as never,
        vulnerabilityAnalyzer: {
          id: 'v',
          version: '1',
          analyze: async () => {
            throw new Error('OSV unavailable');
          }
        }
      });
      expect(
        result.score.dimensions.dependencyHealth.reason ??
          JSON.stringify(result.analysis)
      ).toContain('OSV unavailable');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks hygiene dimensions unavailable when eligible files were skipped', async () => {
    const root = await fixture();
    const analyzer: Analyzer = {
      id: 'test-vulns',
      version: '1',
      analyze: async () => ({
        analyzer: 'test-vulns',
        durationMs: 0,
        findings: []
      })
    };

    try {
      const result = await buildSecurityScorecard(root, {
        dependencyScan: async () => ({
          packages: [packageHealth],
          findings: [],
          summary: cleanSummary
        }),
        doctor: (async () => ({
          findings: [],
          summary: {
            filesDiscovered: 1,
            filesEligible: 1,
            filesScanned: 0,
            filesSkipped: 1,
            readFailures: 0,
            bytesScanned: 0,
            secrets: 0,
            dangerousCode: 0,
            configuration: 0,
            headers: 0
          }
        })) as never,
        gitAudit: cleanGit as never,
        vulnerabilityAnalyzer: analyzer
      });

      expect(result.score.secretHygiene).toBeNull();
      expect(result.score.configurationSecurity).toBeNull();
      expect(result.score.overall).toBeNull();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it('marks unknown Git observations unmeasured', async () => {
    const root = await fixture();
    const gitFinding = { ...vulnerability(), id: 'git-unknown' };
    try {
      const result = await buildSecurityScorecard(root, {
        dependencyScan: async () => ({
          packages: [packageHealth],
          findings: [],
          summary: cleanSummary,
          failures: [],
          coverage: {
            state: 'complete',
            eligible: 1,
            scanned: 1,
            skipped: 0,
            failed: 0
          }
        }),
        doctor: cleanDoctor as never,
        gitAudit: (async () => ({
          findings: [gitFinding],
          summary: {
            ...(await cleanGit()).summary,
            ignoreStatus: 'unknown',
            trackedSensitiveFiles: 0
          }
        })) as never,
        vulnerabilityAnalyzer: {
          id: 'clean-vulns',
          version: '1',
          analyze: async () => ({
            analyzer: 'clean-vulns',
            durationMs: 0,
            findings: []
          })
        }
      });
      expect(result.analysis.state).toBe('partial');
      expect(result.score.dimensions.gitSafety.status).toBe('unavailable');
      expect(result.findings.map((finding) => finding.id)).toContain(
        'git-unknown'
      );
      expect(result.coverage).toMatchObject({
        state: 'partial',
        eligible: 2,
        scanned: 2,
        skipped: 0,
        failed: 0
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('round-trips coverage through scorecard and reports', async () => {
    const root = await fixture();
    try {
      const result = await buildSecurityScorecard(root, {
        dependencyScan: async () => ({
          packages: [packageHealth],
          findings: [],
          summary: cleanSummary,
          failures: [],
          coverage: {
            state: 'partial',
            eligible: 3,
            scanned: 2,
            skipped: 1,
            failed: 0
          }
        }),
        doctor: (async () => {
          const doctor = await cleanDoctor();
          return {
            ...doctor,
            summary: {
              ...doctor.summary,
              filesDiscovered: 2,
              filesEligible: 2,
              filesScanned: 1,
              filesSkipped: 1
            },
            coverage: {
              state: 'partial',
              eligible: 2,
              scanned: 1,
              skipped: 1,
              failed: 0
            }
          };
        }) as never,
        gitAudit: cleanGit as never,
        vulnerabilityAnalyzer: {
          id: 'clean-vulns',
          version: '1',
          analyze: async () => ({
            analyzer: 'clean-vulns',
            durationMs: 0,
            findings: []
          })
        }
      });
      const totals = {
        state: 'partial',
        eligible: 5,
        scanned: 3,
        skipped: 2,
        failed: 0,
        excluded: 0
      };
      expect(result.coverage).toMatchObject(totals);
      const report = createReport({
        version: '2.2.1',
        command: 'scan',
        root,
        findings: result.findings,
        analysis: { ...result.analysis, coverage: result.coverage }
      });
      expect(JSON.parse(JSON.stringify(report)).analysis.coverage).toMatchObject(
        totals
      );
      const markdown = renderMarkdownReport(report);
      expect(markdown).toContain('- Eligible: 5');
      expect(markdown).toContain('- Scanned: 3');
      expect(markdown).toContain('- Skipped: 2');
      expect(markdown).toContain('- Failed: 0');
      expect(markdown).toContain('- Excluded: 0');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

});
