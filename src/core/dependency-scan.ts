import { createHash } from 'node:crypto';
import { mapConcurrent } from '../application/concurrency.js';
import { coverageOf, type AnalysisCoverage } from '../contracts/analysis.js';
import type { Finding } from '../contracts/finding.js';
import { analyzePackage } from './analyze-package.js';
import {
  readNpmDependencyGraph,
  type DependencyFileSource,
  type DependencyIdentity
} from './dependencies/inventory.js';
import type { DependencyInfo, PackageHealth } from './dependency-types.js';
import { readDependencies } from './read-dependencies.js';
import { ProviderError, type ScanBudget } from './scan-budget.js';

export type DependencyLookupFailure = {
  name: string;
  version?: string;
  requirement?: string;
  kind: 'timed_out' | 'cancelled' | 'unavailable' | 'failed' | 'unresolved';
  message: string;
};

export type DependencyScanOptions = {
  /** Deadline, cancellation and request limits shared by every registry call. */
  budget?: ScanBudget;
  /** Concurrency when no budget is supplied. Default 8. */
  concurrency?: number;
  /** Disable registry lookups; unavailable package-health facts stay unknown. */
  offline?: boolean;
  /** Explicitly permit public-registry metadata requests for scoped packages. */
  allowPublicScope?: boolean;
  /** Immutable captured lockfile and manifest contents from the shared scan snapshot. */
  fileSource?: DependencyFileSource;
  /** Reuse parsed graph facts only; provider health remains time-sensitive. */
  inventoryCache?: {
    get<T>(
      snapshotId: string,
      taskId: string,
      taskVersion: string
    ): T | undefined;
    set<T>(
      snapshotId: string,
      taskId: string,
      taskVersion: string,
      value: T
    ): void;
  };
  /** Digest of manifests, lockfiles and package-manager settings in the snapshot. */
  inventoryCacheKey?: string;
};

export type DependencyScanResult = {
  /** Exact lockfile instances, including path and registry, reused by downstream analyzers. */
  identities?: DependencyIdentity[];
  packages: PackageHealth[];
  findings: Finding[];
  /** Packages whose registry lookup did not complete. Never counted as healthy. */
  failures: DependencyLookupFailure[];
  coverage: AnalysisCoverage;
  summary: {
    totalDependencies: number;
    outdated: number;
    deprecated: number;
    highRisk: number;
    mediumRisk: number;
    lowRisk: number;
    averageRiskScore: number;
  };
  inventoryCacheHit?: boolean;
};

type DependencyScanInputs = {
  dependencies: DependencyInfo[];
  identities: DependencyIdentity[];
  totalDependencies: number;
  unresolvedDependencies: DependencyInfo[];
  graphWarnings: string[];
};

function dependencyKey(
  dependency: Pick<DependencyIdentity, 'name' | 'version' | 'registry'>
): string {
  return `${dependency.registry ?? 'unknown'}:${dependency.name}@${dependency.version}`;
}

function dependencyInfo(dependency: DependencyIdentity): DependencyInfo {
  return {
    name: dependency.name,
    version: dependency.version,
    ...(dependency.registry ? { registry: dependency.registry } : {}),
    type: dependency.development ? 'devDependency' : 'dependency'
  };
}

async function readDependencyScanInputs(
  root: string,
  fileSource?: DependencyFileSource,
  options: Pick<
    DependencyScanOptions,
    'inventoryCache' | 'inventoryCacheKey'
  > = {}
): Promise<DependencyScanInputs & { cacheHit: boolean }> {
  const cacheKey =
    options.inventoryCache && options.inventoryCacheKey
      ? createHash('sha256')
          .update(root)
          .update('\0')
          .update(options.inventoryCacheKey)
          .digest('hex')
      : undefined;
  if (cacheKey) {
    const cached = options.inventoryCache?.get<DependencyScanInputs>(
      'dependency-inventory',
      cacheKey,
      'dependency-inventory-v1'
    );
    if (cached) return { ...cached, cacheHit: true };
  }
  const read = async (): Promise<DependencyScanInputs> => {
    try {
      const graph = await readNpmDependencyGraph(root, fileSource);
      const uniqueDependencies = new Map<string, DependencyInfo>();

      for (const dependency of graph.packages) {
        const key = dependencyKey(dependency);
        if (!uniqueDependencies.has(key)) {
          uniqueDependencies.set(key, dependencyInfo(dependency));
        }
      }

      return {
        dependencies: [...uniqueDependencies.values()],
        identities: graph.packages,
        totalDependencies:
          graph.packages.length + graph.unresolvedDependencies.length,
        unresolvedDependencies: graph.unresolvedDependencies.map((edge) => ({
          name: edge.name,
          version: edge.requirement,
          type: edge.section
        })),
        graphWarnings: graph.warnings
      };
    } catch (error) {
      const declarations = await readDependencies(root, fileSource);
      const code =
        error && typeof error === 'object' && 'code' in error
          ? String(error.code)
          : 'DEPENDENCY_GRAPH_UNAVAILABLE';
      return {
        dependencies: [],
        identities: [],
        totalDependencies: declarations.length,
        unresolvedDependencies: declarations,
        graphWarnings:
          code === 'ENOENT'
            ? []
            : [`Dependency graph could not be resolved (${code}).`]
      };
    }
  };
  const inputs = await read();
  if (cacheKey)
    options.inventoryCache?.set(
      'dependency-inventory',
      cacheKey,
      'dependency-inventory-v1',
      inputs
    );
  return { ...inputs, cacheHit: false };
}

export async function scanDependencies(
  root: string,
  options: DependencyScanOptions = {}
): Promise<DependencyScanResult> {
  const inputs = await readDependencyScanInputs(
    root,
    options.fileSource,
    options
  );
  const budget = options.budget;

  // Dependency-health facts and score penalties are package/version facts, so
  // npm lockfile projects analyze each exact resolved version once even if npm
  // installs it at more than one path. totalDependencies still reports the
  // complete resolved graph size.
  //
  // A failed or timed-out lookup is recorded and excluded; it is never treated
  // as a healthy package, and the scan reports partial coverage.
  const outcomes = await mapConcurrent(
    inputs.dependencies,
    budget?.maxConcurrentRequests ?? options.concurrency ?? 8,
    async (
      dependency
    ): Promise<
      | { ok: true; health: PackageHealth }
      | { ok: false; failure: DependencyLookupFailure }
    > => {
      if (options.offline) {
        return {
          ok: false,
          failure: {
            name: dependency.name,
            version: dependency.version,
            kind: 'unavailable',
            message:
              'Registry metadata lookups are disabled in offline mode; package health remains unmeasured.'
          }
        };
      }
      if (
        dependency.registry === undefined ||
        !isPublicNpmRegistry(dependency.registry)
      ) {
        return {
          ok: false,
          failure: {
            name: dependency.name,
            version: dependency.version,
            kind: 'unavailable',
            message:
              'Public npm metadata was not queried because the resolved registry origin is missing or is not the public npm registry.'
          }
        };
      }
      if (
        dependency.name.startsWith('@') &&
        options.allowPublicScope !== true
      ) {
        return {
          ok: false,
          failure: {
            name: dependency.name,
            version: dependency.version,
            kind: 'unavailable',
            message:
              'Scoped package metadata was not sent to a public provider; explicit public-scope consent is required.'
          }
        };
      }
      try {
        return { ok: true, health: await analyzePackage(dependency, budget) };
      } catch (error) {
        const kind = error instanceof ProviderError ? error.kind : 'failed';
        return {
          ok: false,
          failure: {
            name: dependency.name,
            version: dependency.version,
            kind,
            message: error instanceof Error ? error.message : String(error)
          }
        };
      }
    }
  );

  const packages = outcomes.flatMap((outcome) =>
    outcome.ok ? [outcome.health] : []
  );
  const failures: DependencyLookupFailure[] = [
    ...inputs.unresolvedDependencies.map((dependency) => ({
      name: dependency.name,
      requirement: dependency.version,
      kind: 'unresolved' as const,
      message:
        'Dependency requirement is not an exact installed package identity.'
    })),
    ...inputs.graphWarnings
      .filter(
        (warning) =>
          !inputs.unresolvedDependencies.some((dependency) =>
            warning.includes(dependency.name)
          )
      )
      .map((message) => ({
        name: 'dependency graph',
        kind: 'unresolved' as const,
        message
      })),
    ...outcomes.flatMap((outcome) => (outcome.ok ? [] : [outcome.failure]))
  ];
  const findings = packages.flatMap(packageToFindings);
  const cancelled = failures.some((failure) => failure.kind === 'cancelled');
  const coverage = coverageOf({
    eligible:
      inputs.dependencies.length +
      inputs.unresolvedDependencies.length +
      inputs.graphWarnings.filter(
        (warning) =>
          !inputs.unresolvedDependencies.some((dependency) =>
            warning.includes(dependency.name)
          )
      ).length,
    scanned: packages.length,
    skipped: failures.filter(
      (f) => f.kind === 'timed_out' || f.kind === 'cancelled'
    ).length,
    failed: failures.filter(
      (f) => f.kind !== 'timed_out' && f.kind !== 'cancelled'
    ).length,
    cancelled
  });

  return {
    identities: inputs.identities,
    packages,
    findings,
    failures,
    coverage,
    summary: {
      totalDependencies: inputs.totalDependencies,
      outdated: packages.filter((pkg) => pkg.outdated).length,
      deprecated: packages.filter((pkg) => pkg.deprecated).length,
      highRisk: packages.filter((pkg) => pkg.riskScore >= 70).length,
      mediumRisk: packages.filter(
        (pkg) => pkg.riskScore >= 40 && pkg.riskScore < 70
      ).length,
      lowRisk: packages.filter((pkg) => pkg.riskScore > 0 && pkg.riskScore < 40)
        .length,
      averageRiskScore:
        packages.length === 0
          ? 0
          : Math.round(
              packages.reduce((total, pkg) => total + pkg.riskScore, 0) /
                packages.length
            )
    },
    ...(options.inventoryCache && options.inventoryCacheKey
      ? { inventoryCacheHit: inputs.cacheHit }
      : {})
  };
}

function isPublicNpmRegistry(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' && url.origin === 'https://registry.npmjs.org'
    );
  } catch {
    return false;
  }
}

export function packageToFindings(pkg: PackageHealth): Finding[] {
  const findings: Finding[] = [];
  const suffix = `${pkg.name}@${pkg.installedVersion}`
    .toUpperCase()
    .replaceAll(/[^A-Z0-9]/g, '-');

  if (pkg.deprecated) {
    findings.push(
      dependencyFinding({
        ruleId: 'TOOLIP-DEP-DEPRECATED',
        id: `TOOLIP-DEP-DEPRECATED-${suffix}`,
        title: `Deprecated package: ${pkg.name}`,
        severity: 'high',
        message: `${pkg.name} is marked as deprecated on the npm registry.`,
        recommendation:
          'Replace deprecated packages with maintained alternatives and review migration notes.',
        evidence: pkg.latestVersion ?? undefined,
        pkg
      })
    );
  }

  if (pkg.outdated) {
    findings.push(
      dependencyFinding({
        ruleId: 'TOOLIP-DEP-OUTDATED',
        id: `TOOLIP-DEP-OUTDATED-${suffix}`,
        title: `Outdated package: ${pkg.name}`,
        severity: 'medium',
        message: `${pkg.name} appears outdated. Installed: ${pkg.installedVersion}. Latest: ${pkg.latestVersion ?? 'unknown'}.`,
        recommendation:
          'Upgrade the package after checking changelogs, breaking changes, and test coverage.',
        evidence: `${pkg.installedVersion} -> ${pkg.latestVersion ?? 'unknown'}`,
        pkg
      })
    );
  }

  if (pkg.maintainers === 0) {
    findings.push(
      dependencyFinding({
        ruleId: 'TOOLIP-DEP-NO-MAINTAINERS',
        id: `TOOLIP-DEP-NO-MAINTAINERS-${suffix}`,
        title: `No visible maintainers: ${pkg.name}`,
        severity: 'medium',
        message: `${pkg.name} has no visible maintainer metadata from the registry response.`,
        recommendation:
          'Review package ownership, repository activity, and whether a better-maintained alternative exists.',
        pkg
      })
    );
  }

  if (pkg.ageInDays !== null && pkg.ageInDays > 730) {
    findings.push(
      dependencyFinding({
        ruleId: 'TOOLIP-DEP-STALE',
        id: `TOOLIP-DEP-STALE-${suffix}`,
        title: `Possibly stale package: ${pkg.name}`,
        severity: 'low',
        message: `${pkg.name} has not had a detected latest publish in more than two years.`,
        recommendation:
          'Confirm whether the package is intentionally stable or abandoned before relying on it.',
        evidence: `${pkg.ageInDays} days`,
        pkg
      })
    );
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
      ? [
          {
            summary: input.evidence,
            fingerprint: `${input.pkg.name}@${input.pkg.installedVersion}:${input.ruleId}`
          }
        ]
      : undefined,
    remediation: { summary: input.recommendation },
    metadata: {
      package: input.pkg.name,
      installedVersion: input.pkg.installedVersion,
      latestVersion: input.pkg.latestVersion
    }
  };
}
