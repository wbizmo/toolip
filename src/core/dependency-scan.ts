import { readDependencies } from './read-dependencies.js';
import { analyzePackage } from './analyze-package.js';
import type { PackageHealth } from './dependency-types.js';
import type { ToolipFinding } from './report.js';

export type DependencyScanResult = {
  packages: PackageHealth[];
  findings: ToolipFinding[];
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

export async function scanDependencies(root: string): Promise<DependencyScanResult> {
  const dependencies = await readDependencies(root);
  const packages = await Promise.all(
    dependencies.map((dependency) => analyzePackage(dependency))
  );

  const findings = packages.flatMap(packageToFindings);

  return {
    packages,
    findings,
    summary: {
      totalDependencies: packages.length,
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

export function packageToFindings(pkg: PackageHealth): ToolipFinding[] {
  const findings: ToolipFinding[] = [];

  if (pkg.deprecated) {
    findings.push({
      id: `TOOLIP-DEP-DEPRECATED-${pkg.name.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
      title: `Deprecated package: ${pkg.name}`,
      severity: 'high',
      category: 'supply-chain',
      message: `${pkg.name} is marked as deprecated on the npm registry.`,
      recommendation: 'Replace deprecated packages with maintained alternatives and review migration notes.',
      evidence: pkg.latestVersion ?? undefined
    });
  }

  if (pkg.outdated) {
    findings.push({
      id: `TOOLIP-DEP-OUTDATED-${pkg.name.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
      title: `Outdated package: ${pkg.name}`,
      severity: 'medium',
      category: 'supply-chain',
      message: `${pkg.name} appears outdated. Installed: ${pkg.installedVersion}. Latest: ${pkg.latestVersion ?? 'unknown'}.`,
      recommendation: 'Upgrade the package after checking changelogs, breaking changes, and test coverage.',
      evidence: `${pkg.installedVersion} -> ${pkg.latestVersion ?? 'unknown'}`
    });
  }

  if (pkg.maintainers === 0) {
    findings.push({
      id: `TOOLIP-DEP-NO-MAINTAINERS-${pkg.name.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
      title: `No visible maintainers: ${pkg.name}`,
      severity: 'medium',
      category: 'supply-chain',
      message: `${pkg.name} has no visible maintainer metadata from the registry response.`,
      recommendation: 'Review package ownership, repository activity, and whether a better-maintained alternative exists.'
    });
  }

  if (pkg.ageInDays !== null && pkg.ageInDays > 730) {
    findings.push({
      id: `TOOLIP-DEP-STALE-${pkg.name.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
      title: `Possibly stale package: ${pkg.name}`,
      severity: 'low',
      category: 'supply-chain',
      message: `${pkg.name} has not had a detected latest publish in more than two years.`,
      recommendation: 'Confirm whether the package is intentionally stable or abandoned before relying on it.',
      evidence: `${pkg.ageInDays} days`
    });
  }

  return findings;
}
