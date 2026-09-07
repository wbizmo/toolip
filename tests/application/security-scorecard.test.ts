import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Analyzer } from '../../src/contracts/analyzer.js';
import type { Finding } from '../../src/contracts/finding.js';
import { buildSecurityScorecard } from '../../src/application/security-scorecard.js';

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
});
