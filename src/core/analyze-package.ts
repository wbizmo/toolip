import semver from 'semver';
import { fetchPackageManifest } from './npm-registry.js';
import { calculateRiskScore } from './risk-score.js';
import type { DependencyInfo, PackageHealth } from './dependency-types.js';

function cleanInstalledVersion(version: string): string | null {
  if (version === 'latest') return null;
  return semver.coerce(version)?.version ?? null;
}

function isOutdated(installedVersion: string, latestVersion: string | null): boolean {
  const cleanedInstalledVersion = cleanInstalledVersion(installedVersion);

  if (!cleanedInstalledVersion || !latestVersion) {
    return false;
  }

  const cleanedLatestVersion = semver.coerce(latestVersion)?.version;

  if (!cleanedLatestVersion) {
    return false;
  }

  return semver.lt(cleanedInstalledVersion, cleanedLatestVersion);
}

export async function analyzePackage(
  dependency: DependencyInfo
): Promise<PackageHealth> {
  const manifest = await fetchPackageManifest(dependency.name);
  const latestVersion = typeof manifest.version === 'string' ? manifest.version : null;

  const publishedDate =
    manifest.time && latestVersion ? manifest.time[latestVersion] ?? null : null;

  const ageInDays = publishedDate
    ? Math.floor(
        (Date.now() - new Date(publishedDate).getTime()) /
          (1000 * 60 * 60 * 24)
      )
    : null;

  const maintainers = Array.isArray(manifest.maintainers)
    ? manifest.maintainers.length
    : 0;

  const deprecated = Boolean(manifest.deprecated);

  return {
    name: dependency.name,
    installedVersion: dependency.version,
    latestVersion,
    outdated: isOutdated(dependency.version, latestVersion),
    deprecated,
    maintainers,
    publishedAt: publishedDate,
    ageInDays,
    downloads: null,
    riskScore: calculateRiskScore({
      deprecated,
      maintainers,
      ageInDays
    })
  };
}
