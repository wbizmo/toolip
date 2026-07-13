import semver from 'semver';
import type {
  PackageHealth
} from './dependency-types.js';
import type {
  ToolipFinding
} from './report.js';

export type ScoreGrade =
  | 'A'
  | 'B'
  | 'C'
  | 'D'
  | 'F';

export type ToolipScore = {
  dependencyHealth: number;
  secretHygiene: number;
  configurationSecurity: number;
  gitSafety: number;
  overall: number;
  grade: ScoreGrade;
};

export type DependencyHealthBreakdown = {
  score: number;
  vulnerabilityPenalty: number;
  deprecationPenalty: number;
  maintenancePenalty: number;
  freshnessPenalty: number;
  outdated: {
    major: number;
    minor: number;
    patch: number;
    unknown: number;
  };
};

export function calculateScore(
  input?: Partial<
    Omit<ToolipScore, 'overall' | 'grade'>
  >
): ToolipScore {
  const dependencyHealth = clamp(
    input?.dependencyHealth ?? 100
  );

  const secretHygiene = clamp(
    input?.secretHygiene ?? 100
  );

  const configurationSecurity = clamp(
    input?.configurationSecurity ?? 100
  );

  const gitSafety = clamp(
    input?.gitSafety ?? 100
  );

  const overall = Math.round(
    (
      dependencyHealth +
      secretHygiene +
      configurationSecurity +
      gitSafety
    ) / 4
  );

  return {
    dependencyHealth,
    secretHygiene,
    configurationSecurity,
    gitSafety,
    overall,
    grade: gradeScore(overall)
  };
}

export function calculateDependencyHealthFromPackages(
  packages: PackageHealth[],
  vulnerabilityFindings: ToolipFinding[] = []
): DependencyHealthBreakdown {
  let criticalVulnerabilities = 0;
  let highVulnerabilities = 0;
  let mediumVulnerabilities = 0;
  let lowVulnerabilities = 0;

  for (const finding of vulnerabilityFindings) {
    if (
      finding.category !== 'vulnerability'
    ) {
      continue;
    }

    if (finding.severity === 'critical') {
      criticalVulnerabilities += 1;
    } else if (finding.severity === 'high') {
      highVulnerabilities += 1;
    } else if (finding.severity === 'medium') {
      mediumVulnerabilities += 1;
    } else if (finding.severity === 'low') {
      lowVulnerabilities += 1;
    }
  }

  const vulnerabilityPenalty = Math.min(
    100,
    criticalVulnerabilities * 40 +
      highVulnerabilities * 25 +
      mediumVulnerabilities * 12 +
      lowVulnerabilities * 4
  );

  const deprecated = packages.filter(
    (pkg) => pkg.deprecated
  ).length;

  const noMaintainers = packages.filter(
    (pkg) => pkg.maintainers === 0
  ).length;

  const stale = packages.filter(
    (pkg) =>
      pkg.ageInDays !== null &&
      pkg.ageInDays > 730
  ).length;

  const outdated = {
    major: 0,
    minor: 0,
    patch: 0,
    unknown: 0
  };

  for (const pkg of packages) {
    if (
      !pkg.outdated ||
      !pkg.latestVersion
    ) {
      continue;
    }

    const installed = semver.coerce(
      pkg.installedVersion
    );

    const latest = semver.coerce(
      pkg.latestVersion
    );

    if (!installed || !latest) {
      outdated.unknown += 1;
      continue;
    }

    if (latest.major > installed.major) {
      outdated.major += 1;
    } else if (
      latest.minor > installed.minor
    ) {
      outdated.minor += 1;
    } else if (
      latest.patch > installed.patch
    ) {
      outdated.patch += 1;
    } else {
      outdated.unknown += 1;
    }
  }

  const deprecationPenalty = Math.min(
    40,
    deprecated * 18
  );

  const maintenancePenalty = Math.min(
    20,
    noMaintainers * 4
  );

  const freshnessPenalty = Math.min(
    15,
    outdated.major * 3 +
      outdated.minor * 1 +
      outdated.patch * 0.25 +
      outdated.unknown * 1 +
      stale * 1
  );

  const score = clamp(
    100 -
      vulnerabilityPenalty -
      deprecationPenalty -
      maintenancePenalty -
      freshnessPenalty
  );

  return {
    score,
    vulnerabilityPenalty,
    deprecationPenalty,
    maintenancePenalty,
    freshnessPenalty:
      Math.round(freshnessPenalty * 100) /
      100,
    outdated
  };
}

/**
 * Backward-compatible finding-based score.
 *
 * Outdated-package findings are treated as maintenance
 * signals and capped so they cannot independently collapse
 * dependency health to zero.
 */
export function calculateDependencyHealth(
  findings: ToolipFinding[]
): number {
  let vulnerabilityPenalty = 0;
  let deprecationPenalty = 0;
  let maintenancePenalty = 0;
  let freshnessPenalty = 0;

  for (const finding of findings) {
    if (
      finding.category === 'vulnerability'
    ) {
      vulnerabilityPenalty +=
        severityPenalty(finding.severity);

      continue;
    }

    if (
      finding.id.startsWith(
        'TOOLIP-DEP-DEPRECATED-'
      )
    ) {
      deprecationPenalty += 18;
      continue;
    }

    if (
      finding.id.startsWith(
        'TOOLIP-DEP-OUTDATED-'
      )
    ) {
      freshnessPenalty += 1;
      continue;
    }

    if (
      finding.id.startsWith(
        'TOOLIP-DEP-NO-MAINTAINERS-'
      )
    ) {
      maintenancePenalty += 4;
      continue;
    }

    if (
      finding.id.startsWith(
        'TOOLIP-DEP-STALE-'
      )
    ) {
      freshnessPenalty += 1;
      continue;
    }

    maintenancePenalty += Math.min(
      10,
      severityPenalty(finding.severity)
    );
  }

  return clamp(
    100 -
      Math.min(100, vulnerabilityPenalty) -
      Math.min(40, deprecationPenalty) -
      Math.min(20, maintenancePenalty) -
      Math.min(15, freshnessPenalty)
  );
}

function severityPenalty(
  severity: ToolipFinding['severity']
): number {
  if (severity === 'critical') return 40;
  if (severity === 'high') return 25;
  if (severity === 'medium') return 12;
  if (severity === 'low') return 4;
  return 0;
}

function clamp(value: number): number {
  return Math.max(
    0,
    Math.min(100, Math.round(value))
  );
}

export function gradeScore(
  score: number
): ScoreGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
