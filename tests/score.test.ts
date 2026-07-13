import {
  describe,
  expect,
  it
} from 'vitest';
import type {
  PackageHealth
} from '../src/core/dependency-types.js';
import {
  calculateDependencyHealth,
  calculateDependencyHealthFromPackages,
  calculateScore,
  gradeScore
} from '../src/core/score.js';

function packageHealth(
  input: Partial<PackageHealth> & {
    name: string;
  }
): PackageHealth {
  return {
    name: input.name,
    installedVersion:
      input.installedVersion ?? '1.0.0',
    latestVersion:
      input.latestVersion ?? '1.0.0',
    outdated:
      input.outdated ?? false,
    deprecated:
      input.deprecated ?? false,
    maintainers:
      input.maintainers ?? 2,
    publishedAt:
      input.publishedAt ?? null,
    ageInDays:
      input.ageInDays ?? 30,
    downloads:
      input.downloads ?? null,
    riskScore:
      input.riskScore ?? 0
  };
}

describe('score', () => {
  it('calculates default perfect score', () => {
    const score = calculateScore();

    expect(score.overall).toBe(100);
    expect(score.grade).toBe('A');
  });

  it('calculates weighted score average', () => {
    const score = calculateScore({
      dependencyHealth: 90,
      secretHygiene: 80,
      configurationSecurity: 70,
      gitSafety: 60
    });

    expect(score.overall).toBe(75);
    expect(score.grade).toBe('C');
  });

  it('grades scores', () => {
    expect(gradeScore(95)).toBe('A');
    expect(gradeScore(85)).toBe('B');
    expect(gradeScore(75)).toBe('C');
    expect(gradeScore(65)).toBe('D');
    expect(gradeScore(30)).toBe('F');
  });

  it('does not collapse dependency health because packages are only outdated', () => {
    const packages = Array.from(
      {
        length: 11
      },
      (_, index) =>
        packageHealth({
          name: `package-${index}`,
          installedVersion: '1.0.0',
          latestVersion: '1.1.0',
          outdated: true
        })
    );

    const health =
      calculateDependencyHealthFromPackages(
        packages
      );

    expect(health.score).toBeGreaterThanOrEqual(
      85
    );

    expect(
      health.vulnerabilityPenalty
    ).toBe(0);

    expect(
      health.freshnessPenalty
    ).toBeLessThanOrEqual(15);
  });

  it('weights patch updates less than minor and major updates', () => {
    const health =
      calculateDependencyHealthFromPackages(
        [
          packageHealth({
            name: 'patch-package',
            installedVersion: '1.0.0',
            latestVersion: '1.0.1',
            outdated: true
          }),
          packageHealth({
            name: 'minor-package',
            installedVersion: '1.0.0',
            latestVersion: '1.1.0',
            outdated: true
          }),
          packageHealth({
            name: 'major-package',
            installedVersion: '1.0.0',
            latestVersion: '2.0.0',
            outdated: true
          })
        ]
      );

    expect(health.outdated.patch).toBe(1);
    expect(health.outdated.minor).toBe(1);
    expect(health.outdated.major).toBe(1);
    expect(health.freshnessPenalty).toBe(
      4.25
    );
  });

  it('gives disclosed vulnerabilities substantially more weight than freshness', () => {
    const health =
      calculateDependencyHealthFromPackages(
        [
          packageHealth({
            name: 'outdated-package',
            installedVersion: '1.0.0',
            latestVersion: '2.0.0',
            outdated: true
          })
        ],
        [
          {
            id: 'TLP-CVE-TEST',
            title: 'Known vulnerability',
            severity: 'critical',
            category: 'vulnerability',
            message: 'Known vulnerability',
            recommendation: 'Upgrade'
          }
        ]
      );

    expect(
      health.vulnerabilityPenalty
    ).toBe(40);

    expect(
      health.freshnessPenalty
    ).toBe(3);

    expect(health.score).toBe(57);
  });

  it('caps maintenance-only finding penalties', () => {
    const findings = Array.from(
      {
        length: 30
      },
      (_, index) => ({
        id:
          `TOOLIP-DEP-OUTDATED-PACKAGE-${index}`,
        title: 'Outdated package',
        severity: 'medium' as const,
        category: 'supply-chain',
        message: 'Outdated',
        recommendation: 'Upgrade'
      })
    );

    expect(
      calculateDependencyHealth(findings)
    ).toBe(85);
  });
});
