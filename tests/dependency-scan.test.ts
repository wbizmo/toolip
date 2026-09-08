import { describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const analyzePackageMock = vi.hoisted(() => vi.fn(
  async (dependency: { name: string; version: string }) => ({
    name: dependency.name,
    installedVersion: dependency.version,
    latestVersion: dependency.name === 'request' ? '2.88.2' : '10.0.0',
    outdated: dependency.name === 'old-lib',
    deprecated: dependency.name === 'request' || dependency.name === 'duplicate',
    maintainers: dependency.name === 'orphan-lib' ? 0 : 2,
    publishedAt: null,
    ageInDays: dependency.name === 'stale-lib' ? 900 : null,
    downloads: null,
    riskScore: dependency.name === 'request' || dependency.name === 'duplicate' ? 70 : 10
  })
));

vi.mock('../src/core/analyze-package.js', () => ({
  analyzePackage: analyzePackageMock
}));

describe('scanDependencies', () => {
  it('uses exact resolved transitive versions instead of package.json specifiers', async () => {
    analyzePackageMock.mockClear();
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-deps-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            wrapper: 'workspace:*',
            alias: 'npm:actual-package@^1.0.0',
            tagged: 'latest',
            gitdep: 'github:example/repo'
          }
        })
      );
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: {
                wrapper: 'workspace:*'
              }
            },
            'node_modules/wrapper': {
              version: '1.2.3',
              dependencies: {
                request: '^2.0.0',
                'old-lib': '^1.0.0'
              }
            },
            'node_modules/request': {
              version: '2.88.2'
            },
            'node_modules/old-lib': {
              version: '1.4.7',
              dependencies: {
                'orphan-lib': '^3.0.0'
              }
            },
            'node_modules/orphan-lib': {
              version: '3.1.0',
              dependencies: {
                'stale-lib': '^4.0.0'
              }
            },
            'node_modules/stale-lib': {
              version: '4.0.2'
            }
          }
        })
      );

      const { scanDependencies } = await import('../src/core/dependency-scan.js');
      const result = await scanDependencies(root);
      const analyzed = analyzePackageMock.mock.calls.map(([dependency]) => dependency);

      expect(result.summary.totalDependencies).toBe(5);
      expect(result.packages).toHaveLength(5);
      expect(result.summary.deprecated).toBe(1);
      expect(result.summary.outdated).toBe(1);
      expect('dependencyHealth' in result).toBe(false);
      expect(analyzed).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'wrapper', version: '1.2.3' }),
        expect.objectContaining({ name: 'request', version: '2.88.2' }),
        expect.objectContaining({ name: 'old-lib', version: '1.4.7' }),
        expect.objectContaining({ name: 'orphan-lib', version: '3.1.0' }),
        expect.objectContaining({ name: 'stale-lib', version: '4.0.2' })
      ]));
      expect(analyzed.some((dependency) => dependency.version === 'workspace:*')).toBe(false);
      expect(analyzed.some((dependency) => dependency.version === 'latest')).toBe(false);
      expect(result.findings.some((finding) => finding.id.includes('DEPRECATED-REQUEST-2-88-2'))).toBe(true);
      expect(result.findings.some((finding) => finding.id.includes('OUTDATED-OLD-LIB-1-4-7'))).toBe(true);
      expect(result.findings.some((finding) => finding.id.includes('NO-MAINTAINERS'))).toBe(true);
      expect(result.findings.some((finding) => finding.id.includes('STALE'))).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps findings unique when multiple resolved versions of one transitive package exist', async () => {
    analyzePackageMock.mockClear();
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-deps-versions-'));

    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: {
                first: '^1.0.0',
                second: '^1.0.0'
              }
            },
            'node_modules/first': {
              version: '1.0.0',
              dependencies: {
                duplicate: '^1.0.0'
              }
            },
            'node_modules/first/node_modules/duplicate': {
              version: '1.0.0'
            },
            'node_modules/second': {
              version: '1.0.0',
              dependencies: {
                duplicate: '^2.0.0'
              }
            },
            'node_modules/second/node_modules/duplicate': {
              version: '2.0.0'
            }
          }
        })
      );

      const { scanDependencies } = await import('../src/core/dependency-scan.js');
      const result = await scanDependencies(root);
      const duplicateFindings = result.findings.filter(
        (finding) => finding.ruleId === 'TOOLIP-DEP-DEPRECATED' &&
          finding.metadata?.package === 'duplicate'
      );

      expect(result.summary.totalDependencies).toBe(4);
      expect(result.packages).toHaveLength(4);
      expect(duplicateFindings.map((finding) => finding.id).sort()).toEqual([
        'TOOLIP-DEP-DEPRECATED-DUPLICATE-1-0-0',
        'TOOLIP-DEP-DEPRECATED-DUPLICATE-2-0-0'
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('preserves manifest-only dependency scanning when package-lock.json is absent', async () => {
    analyzePackageMock.mockClear();
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-deps-manifest-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            request: '^2.0.0'
          },
          devDependencies: {
            'old-lib': '~1.4.0'
          }
        })
      );

      const { scanDependencies } = await import('../src/core/dependency-scan.js');
      const result = await scanDependencies(root);
      const analyzed = analyzePackageMock.mock.calls.map(([dependency]) => dependency);

      expect(result.summary.totalDependencies).toBe(2);
      expect(result.packages).toHaveLength(2);
      expect(analyzed).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'request', version: '^2.0.0' }),
        expect.objectContaining({ name: 'old-lib', version: '~1.4.0' })
      ]));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
