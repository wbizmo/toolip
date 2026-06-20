import { analyzePackage } from './analyze-package.js';
import type { DependencyInfo, PackageHealth } from './dependency-types.js';

export type PackageComparison = {
  packages: PackageHealth[];
  safest: PackageHealth | null;
  riskiest: PackageHealth | null;
};

function asDependency(packageName: string): DependencyInfo {
  return {
    name: packageName,
    version: 'latest',
    type: 'dependency'
  };
}

export async function comparePackages(packageNames: string[]): Promise<PackageComparison> {
  const uniqueNames = [...new Set(packageNames.map((name) => name.trim()).filter(Boolean))];

  const packages = await Promise.all(
    uniqueNames.map((packageName) => analyzePackage(asDependency(packageName)))
  );

  const sortedByRisk = [...packages].sort((a, b) => a.riskScore - b.riskScore);

  return {
    packages,
    safest: sortedByRisk[0] ?? null,
    riskiest: sortedByRisk.at(-1) ?? null
  };
}
