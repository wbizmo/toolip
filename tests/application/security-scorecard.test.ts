import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import type { Analyzer } from '../../src/contracts/analyzer.js';
import type { Finding } from '../../src/contracts/finding.js';
import { buildSecurityScorecard } from '../../src/application/security-scorecard.js';
import { createReport } from '../../src/core/report.js';
import { renderMarkdownReport } from '../../src/core/report-writer.js';
import * as fileWalker from '../../src/core/file-walker.js';
import { createScannerContext } from '../../src/core/scanner-context.js';
import { createProjectSnapshot } from '../../src/application/project-snapshot.js';
import { AnalysisResultCache } from '../../src/application/task-scheduler.js';
import { runSecurityDoctor } from '../../src/core/security-doctor.js';
import { coverageOf } from '../../src/contracts/analysis.js';
import type { DependencyIdentity } from '../../src/core/dependencies/inventory.js';
import type { PackageHealthAnalysis } from '../../src/core/package-health-analysis.js';
import { analyzeLicenses } from '../../src/core/license-analysis.js';
import {
  canonicalEvidenceJson,
  signReportEvidence,
  verifyReportEvidence
} from '../../src/core/report-signature.js';
import { loadRulePackFile } from '../../src/core/rule-packs.js';
import { parseNpmProvenancePolicy } from '../../src/providers/npm/provenance.js';

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
  it('binds verified rule-pack identity into the signed scorecard subject', async () => {
    const root = await fixture();
    const now = Date.now();
    const payload = {
      schema: 'toolip.dev/rule-pack/v1',
      id: 'scorecard',
      apiVersion: 1,
      issuedAt: new Date(now - 1_000).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
      rules: [
        {
          id: 'TLP-SCORECARD-001',
          title: 'Scorecard integration marker',
          severity: 'low',
          confidence: 'high',
          literal: 'SCORECARD_RULEPACK_MARKER',
          fileExtensions: ['.ts'],
          remediation: 'Remove the marker.'
        }
      ]
    };
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();
    const privateKeyPem = privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const keyId = 'scorecard-policy-v1';
    const dependencyGraphDigest = 'b'.repeat(64);
    const packPath = path.join(root, 'rule-pack.json');
    await writeFile(
      packPath,
      JSON.stringify({
        ...payload,
        signature: {
          algorithm: 'Ed25519',
          keyId,
          value: cryptoSign(
            null,
            Buffer.from(canonicalEvidenceJson(payload)),
            privateKey
          ).toString('base64')
        }
      })
    );
    const rulePack = await loadRulePackFile(packPath, {
      publicKeyPem,
      trustedKeyId: keyId,
      now
    });
    const scannerContext = await createScannerContext(root);
    const projectSnapshot = await createProjectSnapshot(root, {
      discoveredFiles: scannerContext.files
    });
    const analyzer: Analyzer = {
      id: 'test-vulns',
      version: '1',
      analyze: async () => ({
        analyzer: 'test-vulns',
        durationMs: 0,
        findings: [],
        coverage: {
          state: 'complete',
          eligible: 0,
          scanned: 0,
          skipped: 0,
          failed: 0
        }
      })
    };

    try {
      const scorecard = await buildSecurityScorecard(
        root,
        {
          dependencyScan: async () => ({
            packages: [],
            findings: [],
            failures: [],
            dependencyGraphDigest,
            coverage: {
              state: 'complete',
              eligible: 0,
              scanned: 0,
              skipped: 0,
              failed: 0
            },
            summary: {
              totalDependencies: 0,
              outdated: 0,
              deprecated: 0,
              highRisk: 0,
              mediumRisk: 0,
              lowRisk: 0,
              averageRiskScore: 0
            }
          }),
          doctor: cleanDoctor as never,
          gitAudit: cleanGit as never,
          vulnerabilityAnalyzer: analyzer
        },
        {
          offline: true,
          scannerContext,
          projectSnapshot,
          rulePacks: [rulePack]
        }
      );
      expect(scorecard.evidenceSubject).toMatchObject({
        dependencyGraphDigest,
        rulePacks: [
          {
            id: rulePack.id,
            sha256: rulePack.sha256,
            trust: 'signature',
            keyId
          }
        ]
      });

      const signed = signReportEvidence(
        createReport({
          version: '3.2.1-rc',
          command: 'scan',
          root,
          findings: scorecard.findings,
          analysis: { ...scorecard.analysis, coverage: scorecard.coverage }
        }),
        {
          privateKeyPem,
          keyId: 'evidence-key-v1',
          projectId: 'org/project',
          scannerArtifactSha256: 'd'.repeat(64),
          issuedAt: '2026-11-01T00:00:00.000Z',
          subject: scorecard.evidenceSubject
        }
      );
      expect(
        verifyReportEvidence(signed, {
          publicKeyPem,
          trustedKeyId: 'evidence-key-v1',
          expectedProjectId: 'org/project',
          now: Date.parse('2026-11-02T00:00:00.000Z')
        }).status
      ).toBe('verified');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('runs cold and warm analyses over one immutable snapshot with identical findings', async () => {
    const root = await fixture();
    await writeFile(path.join(root, 'src.ts'), 'export const stable = true;\n');
    const scannerContext = await createScannerContext(root);
    const projectSnapshot = await createProjectSnapshot(root, {
      discoveredFiles: scannerContext.files
    });
    const analysisCache = new AnalysisResultCache();
    const analyzer: Analyzer = {
      id: 'test-vulns',
      version: '1',
      analyze: async () => ({
        analyzer: 'test-vulns',
        durationMs: 0,
        findings: [vulnerability()],
        coverage: {
          state: 'complete',
          eligible: 1,
          scanned: 1,
          skipped: 0,
          failed: 0
        }
      })
    };
    const services = {
      dependencyScan: async () => ({
        packages: [packageHealth],
        findings: [],
        failures: [],
        coverage: {
          state: 'complete' as const,
          eligible: 1,
          scanned: 1,
          skipped: 0,
          failed: 0
        },
        summary: cleanSummary
      }),
      doctor: runSecurityDoctor,
      gitAudit: cleanGit,
      vulnerabilityAnalyzer: analyzer
    };
    const options = {
      scannerContext,
      projectSnapshot,
      analysisCache
    };

    try {
      const cold = await buildSecurityScorecard(root, services, options);
      const warm = await buildSecurityScorecard(root, services, options);
      expect(cold.snapshotId).toBe(projectSnapshot.id);
      expect(warm.snapshotId).toBe(projectSnapshot.id);
      expect(cold.findings).toEqual(warm.findings);
      expect(cold.cacheMetrics.misses).toBeGreaterThan(0);
      expect(warm.cacheMetrics.hits).toBeGreaterThan(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

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

  it('reuses the command scanner context instead of walking the project again', async () => {
    const root = await fixture();
    try {
      const scannerContext = await createScannerContext(root);
      const walkSpy = vi.spyOn(fileWalker, 'walkProjectFiles');
      const result = await buildSecurityScorecard(
        root,
        {
          dependencyScan: async () => ({
            packages: [packageHealth],
            findings: [],
            summary: cleanSummary
          }),
          doctor: cleanDoctor as never,
          gitAudit: cleanGit as never,
          vulnerabilityAnalyzer: {
            id: 'test-vulns',
            version: '1',
            analyze: async () => ({
              analyzer: 'test-vulns',
              durationMs: 0,
              findings: []
            })
          }
        },
        { scannerContext }
      );

      expect(result.score.complete).toBe(true);
      expect(walkSpy).not.toHaveBeenCalled();
      walkSpy.mockRestore();
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
      const serialized = JSON.parse(JSON.stringify(report));
      expect(serialized.analysis.coverage).toMatchObject(totals);
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

  it('joins opt-in package-history signals to exact instances in the shared scorecard', async () => {
    const root = await fixture();
    const identity: DependencyIdentity = {
      ecosystem: 'npm',
      name: 'safe-package',
      version: '1.2.3',
      installPath: 'node_modules/safe-package',
      registry: 'https://registry.npmjs.org',
      development: false
    };
    const reviewSignal: Finding = {
      ...vulnerability(),
      id: 'TLP-NPM-HEALTH-RELEASE-BURST:instance',
      ruleId: 'TLP-NPM-HEALTH-RELEASE-BURST',
      title: 'Unusual package release burst',
      category: 'supply-chain',
      severity: 'medium',
      source: 'npm-package-health'
    };
    const health: PackageHealthAnalysis = {
      coverage: coverageOf({
        eligible: 1,
        scanned: 1,
        skipped: 0,
        failed: 0
      }),
      observations: [],
      findings: [reviewSignal],
      warnings: []
    };
    const inspect = vi.fn(async (identities: DependencyIdentity[]) => {
      expect(identities).toEqual([identity]);
      return health;
    });

    try {
      const result = await buildSecurityScorecard(
        root,
        {
          dependencyScan: async () => ({
            identities: [identity],
            packages: [packageHealth],
            findings: [],
            failures: [],
            coverage: coverageOf({
              eligible: 1,
              scanned: 1,
              skipped: 0,
              failed: 0
            }),
            summary: cleanSummary
          }),
          doctor: cleanDoctor as never,
          gitAudit: cleanGit as never,
          vulnerabilityAnalyzer: {
            id: 'clean-vulns',
            version: '1',
            analyze: async () => ({
              analyzer: 'clean-vulns',
              durationMs: 0,
              findings: []
            })
          },
          packageHealth: inspect
        },
        { includePackageHealth: true }
      );

      expect(inspect).toHaveBeenCalledTimes(1);
      expect(result.packageHealth).toEqual(health);
      expect(result.findings).toContainEqual(reviewSignal);
      expect(result.analysis.state).toBe('complete');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks an opted-in scorecard incomplete when package provenance is untrusted', async () => {
    const root = await fixture();
    const verification = {
      identityDigest: 'd'.repeat(64),
      name: 'example',
      version: '1.0.0',
      status: 'untrusted' as const,
      reason: 'repository_mismatch' as const,
      artifactIntegrity: 'declared-not-verified' as const
    };
    const npmProvenancePolicy = parseNpmProvenancePolicy({
      version: 1,
      packages: {
        example: {
          certificateIssuer: 'https://token.actions.githubusercontent.com',
          certificateIdentity:
            'https://github.com/acme/example/.github/workflows/release.yml@refs/tags/v1.0.0',
          sourceRepository: 'https://github.com/acme/example'
        }
      }
    });
    try {
      const result = await buildSecurityScorecard(
        root,
        {
          dependencyScan: async () => ({
            identities: [],
            packages: [packageHealth],
            findings: [],
            failures: [],
            npmProvenance: [verification],
            coverage: coverageOf({
              eligible: 1,
              scanned: 1,
              skipped: 0,
              failed: 0
            }),
            summary: cleanSummary
          }),
          doctor: cleanDoctor as never,
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
        },
        { npmProvenancePolicy }
      );

      expect(result.npmProvenance).toEqual([verification]);
      expect(result.analysis.state).toBe('partial');
      expect(result.score.complete).toBe(false);
      expect(result.score.dimensions.dependencyHealth.status).toBe(
        'unavailable'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not run registry-history review unless explicitly enabled', async () => {
    const root = await fixture();
    const inspect = vi.fn();
    try {
      const result = await buildSecurityScorecard(root, {
        dependencyScan: async () => ({
          identities: [],
          packages: [],
          findings: [],
          failures: [],
          coverage: coverageOf({
            eligible: 0,
            scanned: 0,
            skipped: 0,
            failed: 0
          }),
          summary: { ...cleanSummary, totalDependencies: 0 }
        }),
        doctor: cleanDoctor as never,
        gitAudit: cleanGit as never,
        vulnerabilityAnalyzer: {
          id: 'clean-vulns',
          version: '1',
          analyze: async () => ({
            analyzer: 'clean-vulns',
            durationMs: 0,
            findings: []
          })
        },
        packageHealth: inspect
      });

      expect(inspect).not.toHaveBeenCalled();
      expect(result.packageHealth).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('includes exact license metadata and unknown coverage in the shared scorecard', async () => {
    const root = await fixture();
    const identity: DependencyIdentity = {
      id: 'npm:node_modules/safe-package:safe-package@1.2.3',
      ecosystem: 'npm',
      name: 'safe-package',
      version: '1.2.3',
      direct: true,
      development: false,
      source: 'package-lock',
      resolutionConfidence: 'lockfile',
      installPath: 'node_modules/safe-package',
      registry: 'https://registry.npmjs.org'
    };
    const provider = vi.fn(async () => ({ licenses: ['MIT'] }));
    try {
      const result = await buildSecurityScorecard(
        root,
        {
          dependencyScan: async () => ({
            identities: [identity],
            packages: [packageHealth],
            findings: [],
            failures: [],
            coverage: coverageOf({
              eligible: 1,
              scanned: 1,
              skipped: 0,
              failed: 0
            }),
            summary: cleanSummary
          }),
          doctor: cleanDoctor as never,
          gitAudit: cleanGit as never,
          vulnerabilityAnalyzer: {
            id: 'clean-vulns',
            version: '1',
            analyze: async () => ({
              analyzer: 'clean-vulns',
              durationMs: 0,
              findings: []
            })
          },
          licenseAnalysis: (path, _provider, signal, options) =>
            analyzeLicenses(path, { getVersion: provider }, signal, options)
        },
        { includeLicenseAnalysis: true }
      );

      expect(provider).toHaveBeenCalledWith(
        'safe-package',
        '1.2.3',
        expect.anything()
      );
      expect(result.licenseAnalysis?.licenses).toMatchObject([
        { name: 'safe-package', version: '1.2.3', license: 'MIT' }
      ]);
      expect(result.analysis.state).toBe('complete');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps opted-in license analysis incomplete when offline metadata is unknown', async () => {
    const root = await fixture();
    const identity: DependencyIdentity = {
      id: 'npm:node_modules/private-package:private-package@1.0.0',
      ecosystem: 'npm',
      name: 'private-package',
      version: '1.0.0',
      direct: true,
      development: false,
      source: 'package-lock',
      resolutionConfidence: 'lockfile',
      installPath: 'node_modules/private-package',
      registry: 'https://registry.npmjs.org'
    };
    const provider = vi.fn(async () => ({ licenses: ['MIT'] }));
    try {
      const result = await buildSecurityScorecard(
        root,
        {
          dependencyScan: async () => ({
            identities: [identity],
            packages: [packageHealth],
            findings: [],
            failures: [],
            coverage: coverageOf({
              eligible: 1,
              scanned: 1,
              skipped: 0,
              failed: 0
            }),
            summary: cleanSummary
          }),
          doctor: cleanDoctor as never,
          gitAudit: cleanGit as never,
          vulnerabilityAnalyzer: {
            id: 'clean-vulns',
            version: '1',
            analyze: async () => ({
              analyzer: 'clean-vulns',
              durationMs: 0,
              findings: []
            })
          },
          licenseAnalysis: (path, _provider, signal, options) =>
            analyzeLicenses(path, { getVersion: provider }, signal, options)
        },
        { includeLicenseAnalysis: true, offline: true }
      );

      expect(provider).not.toHaveBeenCalled();
      expect(result.licenseAnalysis?.licenses[0]?.license).toBe('UNKNOWN');
      expect(result.licenseAnalysis?.coverage.state).toBe('failed');
      expect(result.analysis.state).toBe('partial');
      expect(result.analysis.reasons.join(' ')).toContain('license analysis');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
