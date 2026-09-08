import { mapConcurrent } from '../application/concurrency.js';
import type { Finding } from '../contracts/finding.js';
import { analyzePackage } from './analyze-package.js';
import {
  readNpmDependencyInventory,
  type DependencyIdentity
} from './dependencies/inventory.js';
import type { DependencyInfo, PackageHealth } from './dependency-types.js';
import { readDependencies } from './read-dependencies.js';

export type DependencyScanResult = {
  packages: PackageHealth[];
  findings: Finding[];
  summary: {
    totalDependencies: number;
    outdated: number;
    deprecated: number;
    highRisk: number;
    mediumRisk: number;
    lowRisk: number;
    averageRiskScore: number;
  };
};

type DependencyScanInputs = {
  dependencies: DependencyInfo[];
  totalDependencies: number;
};

function dependencyKey(dependency: Pick<DependencyIdentity, 'name' | 'version'>): string {
  return `${dependency.name}@${dependency.version}`;
}

function dependencyInfo(dependency: DependencyIdentity): DependencyInfo {
  return {
    name: dependency.name,
    version: dependency.version,
    type: dependency.development ? 'devDependency' : 'dependency'
  };
}

async function readDependencyScanInputs(root: string): Promise<DependencyScanInputs> {
  try {
    const inventory = await readNpmDependencyInventory(root);
    const uniqueDependencies = new Map<string, DependencyInfo>();

    for (const dependency of inventory) {
      const key = dependencyKey(dependency);
      if (!uniqueDependencies.has(key)) {
        uniqueDependencies.set(key, dependencyInfo(dependency));
      }
    }

    return {
      dependencies: [...uniqueDependencies.values()],
      totalDependencies: inventory.length
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw error;
    }

    // Preserve Toolip's previous manifest-only behavior for projects that do
    // not have an npm package-lock. npm projects with a package-lock always use
    // the canonical exact resolved inventory above.
    const dependencies = await readDependencies(root);
    return {
      dependencies,
      totalDependencies: dependencies.length
    };
  }
}

export async function scanDependencies(root: string): Promise<DependencyScanResult> {
  const inputs = await readDependencyScanInputs(root);

  // Dependency-health facts and score penalties are package/version facts, so
  // npm lockfile projects analyze each exact resolved version once even if npm
  // installs it at more than one path. totalDependencies still reports the
  // complete resolved graph size.
  const packages = await mapConcurrent(
    inputs.dependencies,
    8,
    (dependency) => analyzePackage(dependency)
  );
  const findings = packages.flatMap(packageToFindings);

  return {
    packages,
    findings,
    summary: {
      totalDependencies: inputs.totalDependencies,
      outdated: packages.filter((pkg) => pkg.outdated).length,
      deprecated: packages.filter((pkg) => pkg.deprecated).length,
      highRisk: packages.filter((pkg) => pkg.riskScore >= 70).length,
      mediumRisk: packages.filter((pkg) => pkg.riskScore >= 40 && pkg.riskScore < 70).length,
      lowRisk: packages.filter((pkg) => pkg.riskScore > 0 && pkg.riskScore < 40).length,
      averageRiskScore: packages.length === 0
        ? 0
        : Math.round(packages.reduce((total, pkg) => total + pkg.riskScore, 0) / packages.length)
    }
  };
}

export function packageToFindings(pkg: PackageHealth): Finding[] {
  const findings: Finding[] = [];
  const suffix = `${pkg.name}@${pkg.installedVersion}`
    .toUpperCase()
    .replaceAll(/[^A-Z0-9]/g, '-');

  if (pkg.deprecated) {
    findings.push(dependencyFinding({
      ruleId: 'TOOLIP-DEP-DEPRECATED',
      id: `TOOLIP-DEP-DEPRECATED-${suffix}`,
      title: `Deprecated package: ${pkg.name}`,
      severity: 'high',
      message: `${pkg.name} is marked as deprecated on the npm registry.`,
      recommendation: 'Replace deprecated packages with maintained alternatives and review migration notes.',
      evidence: pkg.latestVersion ?? undefined,
      pkg
    }));
  }

  if (pkg.outdated) {
    findings.push(dependencyFinding({
      ruleId: 'TOOLIP-DEP-OUTDATED',
      id: `TOOLIP-DEP-OUTDATED-${suffix}`,
      title: `Outdated package: ${pkg.name}`,
      severity: 'medium',
      message: `${pkg.name} appears outdated. Installed: ${pkg.installedVersion}. Latest: ${pkg.latestVersion ?? 'unknown'}.`,
      recommendation: 'Upgrade the package after checking changelogs, breaking changes, and test coverage.',
      evidence: `${pkg.installedVersion} -> ${pkg.latestVersion ?? 'unknown'}`,
      pkg
    }));
  }

  if (pkg.maintainers === 0) {
    findings.push(dependencyFinding({
      ruleId: 'TOOLIP-DEP-NO-MAINTAINERS',
      id: `TOOLIP-DEP-NO-MAINTAINERS-${suffix}`,
      title: `No visible maintainers: ${pkg.name}`,
      severity: 'medium',
      message: `${pkg.name} has no visible maintainer metadata from the registry response.`,
      recommendation: 'Review package ownership, repository activity, and whether a better-maintained alternative exists.',
      pkg
    }));
  }

  if (pkg.ageInDays !== null && pkg.ageInDays > 730) {
    findings.push(dependencyFinding({
      ruleId: 'TOOLIP-DEP-STALE',
      id: `TOOLIP-DEP-STALE-${suffix}`,
      title: `Possibly stale package: ${pkg.name}`,
      severity: 'low',
      message: `${pkg.name} has not had a detected latest publish in more than two years.`,
      recommendation: 'Confirm whether the package is intentionally stable or abandoned before relying on it.',
      evidence: `${pkg.ageInDays} days`,
      pkg
    }));
  }

  return findings;
}

function dependencyFinding(input: {
  ruleId: string;
  id: string;
  title: string;
  severity: Finding['severity'];
  message: string;
  recommendation: string;
  evidence?: string;
  pkg: PackageHealth;
}): Finding {
  return {
    id: input.id,
    ruleId: input.ruleId,
    title: input.title,
    severity: input.severity,
    confidence: 'high',
    category: 'supply-chain',
    message: input.message,
    source: 'npm-registry',
    evidence: input.evidence
      ? [{
          summary: input.evidence,
          fingerprint: `${input.pkg.name}@${input.pkg.installedVersion}:${input.ruleId}`
        }]
      : undefined,
    remediation: { summary: input.recommendation },
    metadata: {
      package: input.pkg.name,
      installedVersion: input.pkg.installedVersion,
      latestVersion: input.pkg.latestVersion
    }
  };
}
