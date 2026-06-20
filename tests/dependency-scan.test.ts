import { describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

vi.mock('../src/core/analyze-package.js', () => {
  return {
    analyzePackage: async (dependency: { name: string; version: string }) => {
      return {
        name: dependency.name,
        installedVersion: dependency.version,
        latestVersion: dependency.name === 'request' ? '2.88.2' : '10.0.0',
        outdated: dependency.name === 'old-lib',
        deprecated: dependency.name === 'request',
        maintainers: dependency.name === 'orphan-lib' ? 0 : 2,
        publishedAt: null,
        ageInDays: dependency.name === 'stale-lib' ? 900 : null,
        downloads: null,
        riskScore: dependency.name === 'request' ? 70 : 10
      };
    }
  };
});

describe('scanDependencies', () => {
  it('creates findings for deprecated, outdated, orphaned, and stale packages', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-deps-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            request: '^2.0.0',
            'old-lib': '^1.0.0',
            'orphan-lib': '^1.0.0',
            'stale-lib': '^1.0.0'
          }
        })
      );

      const { scanDependencies } = await import('../src/core/dependency-scan.js');
      const result = await scanDependencies(root);

      expect(result.summary.totalDependencies).toBe(4);
      expect(result.summary.deprecated).toBe(1);
      expect(result.summary.outdated).toBe(1);
      expect(result.findings.some((finding) => finding.id.includes('DEPRECATED'))).toBe(true);
      expect(result.findings.some((finding) => finding.id.includes('OUTDATED'))).toBe(true);
      expect(result.findings.some((finding) => finding.id.includes('NO-MAINTAINERS'))).toBe(true);
      expect(result.findings.some((finding) => finding.id.includes('STALE'))).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
