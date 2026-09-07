import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/contracts/finding.js';
import type { PackageHealth } from '../src/core/dependency-types.js';
import {
  calculateDependencyHealthFromPackages,
  calculateFindingHealth,
  calculateScore,
  gradeScore,
  measuredDimension,
  unmeasuredDimension
} from '../src/core/score.js';

function packageHealth(
  input: Partial<PackageHealth> & { name: string }
): PackageHealth {
  return {
    name: input.name,
    installedVersion: input.installedVersion ?? '1.0.0',
    latestVersion: input.latestVersion ?? '1.0.0',
    outdated: input.outdated ?? false,
    deprecated: input.deprecated ?? false,
    maintainers: input.maintainers ?? 2,
    publishedAt: input.publishedAt ?? null,
    ageInDays: input.ageInDays ?? 30,
    downloads: input.downloads ?? null,
    riskScore: input.riskScore ?? 0
  };
}

function finding(severity: Finding['severity'], category = 'test'): Finding {
  return {
    id: `TEST-${severity}-${category}`,
    ruleId: 'TEST',
    title: 'Test finding',
    severity,
    confidence: 'high',
    category,
    message: 'Test finding',
    source: 'test',
    remediation: { summary: 'Fix it' }
  };
}

describe('score', () => {
  it('refuses to produce an overall score when any dimension is unmeasured', () => {
    const score = calculateScore({
      dependencyHealth: measuredDimension(100),
      secretHygiene: unmeasuredDimension('unavailable', 'Not scanned'),
      configurationSecurity: measuredDimension(100),
      gitSafety: measuredDimension(100)
    });

    expect(score.secretHygiene).toBeNull();
    expect(score.overall).toBeNull();
    expect(score.grade).toBeNull();
    expect(score.complete).toBe(false);
  });

  it('calculates the average only when every dimension was measured', () => {
    const score = calculateScore({
      dependencyHealth: measuredDimension(90),
      secretHygiene: measuredDimension(80),
      configurationSecurity: measuredDimension(70),
      gitSafety: measuredDimension(60)
    });

    expect(score.overall).toBe(75);
    expect(score.grade).toBe('C');
    expect(score.complete).toBe(true);
  });

  it('grades scores', () => {
    expect(gradeScore(95)).toBe('A');
    expect(gradeScore(85)).toBe('B');
    expect(gradeScore(75)).toBe('C');
    expect(gradeScore(65)).toBe('D');
    expect(gradeScore(30)).toBe('F');
  });

  it('scores finding-backed dimensions by observed severity', () => {
    expect(calculateFindingHealth([])).toBe(100);
    expect(calculateFindingHealth([finding('critical')])).toBe(60);
    expect(calculateFindingHealth([finding('high'), finding('medium')])).toBe(63);
  });

  it('does not collapse dependency health because packages are only outdated', () => {
    const packages = Array.from({ length: 11 }, (_, index) =>
      packageHealth({
        name: `package-${index}`,
        installedVersion: '1.0.0',
        latestVersion: '1.1.0',
        outdated: true
      })
    );

    const health = calculateDependencyHealthFromPackages(packages, []);

    expect(health.score).toBeGreaterThanOrEqual(85);
    expect(health.vulnerabilityPenalty).toBe(0);
    expect(health.freshnessPenalty).toBeLessThanOrEqual(15);
  });

  it('weights patch updates less than minor and major updates', () => {
    const health = calculateDependencyHealthFromPackages(
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
      ],
      []
    );

    expect(health.outdated.patch).toBe(1);
    expect(health.outdated.minor).toBe(1);
    expect(health.outdated.major).toBe(1);
    expect(health.freshnessPenalty).toBe(4.25);
  });

  it('uses actual vulnerability findings in dependency health', () => {
    const health = calculateDependencyHealthFromPackages(
      [
        packageHealth({
          name: 'outdated-package',
          installedVersion: '1.0.0',
          latestVersion: '2.0.0',
          outdated: true
        })
      ],
      [finding('critical', 'vulnerability')]
    );

    expect(health.vulnerabilityPenalty).toBe(40);
    expect(health.freshnessPenalty).toBe(3);
    expect(health.score).toBe(57);
  });
});
