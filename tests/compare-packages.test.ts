import { describe, expect, it, vi } from 'vitest';
import type { DependencyInfo } from '../src/core/dependency-types.js';

vi.mock('../src/core/analyze-package.js', () => {
  return {
    analyzePackage: async (dependency: DependencyInfo) => {
      const riskByName: Record<string, number> = {
        safe: 10,
        risky: 80,
        middle: 40
      };

      return {
        name: dependency.name,
        installedVersion: dependency.version,
        latestVersion: '1.0.0',
        outdated: false,
        deprecated: dependency.name === 'risky',
        maintainers: dependency.name === 'risky' ? 0 : 3,
        publishedAt: null,
        ageInDays: null,
        downloads: null,
        riskScore: riskByName[dependency.name] ?? 30
      };
    }
  };
});

describe('comparePackages', () => {
  it('compares packages and identifies safest and riskiest', async () => {
    const { comparePackages } = await import('../src/core/compare-packages.js');

    const comparison = await comparePackages(['risky', 'safe', 'middle', 'safe']);

    expect(comparison.packages).toHaveLength(3);
    expect(comparison.safest?.name).toBe('safe');
    expect(comparison.riskiest?.name).toBe('risky');
  });
});
