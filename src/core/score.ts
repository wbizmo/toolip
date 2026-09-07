import semver from 'semver';
import type {
  Finding,
  FindingSeverity
} from '../contracts/finding.js';
import type { PackageHealth } from './dependency-types.js';

export type ScoreGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export type MeasurementStatus =
  | 'measured'
  | 'failed'
  | 'timed_out'
  | 'cancelled'
  | 'unavailable';

export type ScoreDimension = {
  score: number | null;
  status: MeasurementStatus;
  findings: number;
  reason?: string;
};

export type ScoreDimensions = {
  dependencyHealth: ScoreDimension;
  secretHygiene: ScoreDimension;
  configurationSecurity: ScoreDimension;
  gitSafety: ScoreDimension;
};

export type ToolipScore = {
  dependencyHealth: number | null;
  secretHygiene: number | null;
  configurationSecurity: number | null;
  gitSafety: number | null;
  overall: number | null;
  grade: ScoreGrade | null;
  complete: boolean;
  dimensions: ScoreDimensions;
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

export function measuredDimension(
  score: number,
  findings = 0
): ScoreDimension {
  return {
    score: clamp(score),
    status: 'measured',
    findings
  };
}

export function unmeasuredDimension(
  status: Exclude<MeasurementStatus, 'measured'>,
  reason: string
): ScoreDimension {
  return {
    score: null,
    status,
    findings: 0,
    reason
  };
}

export function calculateScore(
  dimensions: ScoreDimensions
): ToolipScore {
  const values = Object.values(dimensions);
  const complete = values.every(
    (dimension) =>
      dimension.status === 'measured' &&
      dimension.score !== null
  );

  const overall = complete
    ? Math.round(
        values.reduce(
          (total, dimension) => total + (dimension.score ?? 0),
          0
        ) / values.length
      )
    : null;

  return {
    dependencyHealth: dimensions.dependencyHealth.score,
    secretHygiene: dimensions.secretHygiene.score,
    configurationSecurity: dimensions.configurationSecurity.score,
    gitSafety: dimensions.gitSafety.score,
    overall,
    grade: overall === null ? null : gradeScore(overall),
    complete,
    dimensions
  };
}

export function calculateFindingHealth(
  findings: Finding[]
): number {
  const penalty = findings.reduce(
    (total, finding) => total + severityPenalty(finding.severity),
    0
  );

  return clamp(100 - Math.min(100, penalty));
}

export function calculateDependencyHealthFromPackages(
  packages: PackageHealth[],
  vulnerabilityFindings: Finding[]
): DependencyHealthBreakdown {
  let criticalVulnerabilities = 0;
  let highVulnerabilities = 0;
  let mediumVulnerabilities = 0;
  let lowVulnerabilities = 0;

  for (const finding of vulnerabilityFindings) {
    if (finding.category !== 'vulnerability') continue;

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

  const deprecated = packages.filter((pkg) => pkg.deprecated).length;
  const noMaintainers = packages.filter((pkg) => pkg.maintainers === 0).length;
  const stale = packages.filter(
    (pkg) => pkg.ageInDays !== null && pkg.ageInDays > 730
  ).length;

  const outdated = {
    major: 0,
    minor: 0,
    patch: 0,
    unknown: 0
  };

  for (const pkg of packages) {
    if (!pkg.outdated || !pkg.latestVersion) continue;

    const installed = semver.coerce(pkg.installedVersion);
    const latest = semver.coerce(pkg.latestVersion);

    if (!installed || !latest) {
      outdated.unknown += 1;
      continue;
    }

    if (latest.major > installed.major) {
      outdated.major += 1;
    } else if (latest.minor > installed.minor) {
      outdated.minor += 1;
    } else if (latest.patch > installed.patch) {
      outdated.patch += 1;
    } else {
      outdated.unknown += 1;
    }
  }

  const deprecationPenalty = Math.min(40, deprecated * 18);
  const maintenancePenalty = Math.min(20, noMaintainers * 4);
  const freshnessPenalty = Math.min(
    15,
    outdated.major * 3 +
      outdated.minor +
      outdated.patch * 0.25 +
      outdated.unknown +
      stale
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
      Math.round(freshnessPenalty * 100) / 100,
    outdated
  };
}

function severityPenalty(severity: FindingSeverity): number {
  if (severity === 'critical') return 40;
  if (severity === 'high') return 25;
  if (severity === 'medium') return 12;
  if (severity === 'low') return 4;
  return 0;
}

function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

export function gradeScore(score: number): ScoreGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
