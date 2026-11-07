import { createHash } from 'node:crypto';
import { coverageOf, type AnalysisCoverage } from '../contracts/analysis.js';
import type { Finding, FindingSeverity } from '../contracts/finding.js';
import type { DependencyIdentity } from './dependencies/inventory.js';
import {
  NpmPackageHealthClient,
  type NpmPackageHealthObservation
} from '../providers/npm/package-health.js';

export type PackageHealthAnalysisOptions = {
  signal?: AbortSignal;
  offline?: boolean;
  allowPublicScope?: boolean;
  concurrency?: number;
  requestTimeoutMs?: number;
  client?: NpmPackageHealthClient;
};

export type PackageHealthAnalysis = {
  coverage: AnalysisCoverage;
  observations: NpmPackageHealthObservation[];
  findings: Finding[];
  warnings: string[];
};

const ruleTitles: Record<string, string> = {
  'publisher-identity-varies': 'Publisher identity varies across releases',
  'release-burst': 'Unusual package release burst',
  'stale-maintenance': 'Package has stale maintenance activity',
  'maintainer-set-varies': 'Maintainer set varies across releases',
  'new-install-script': 'Installed version adds a lifecycle script',
  'repository-identity-changed': 'Package repository identity varies',
  'package-deprecated': 'Package is marked deprecated'
};

function findingFor(
  observation: NpmPackageHealthObservation,
  signalId: string,
  evidence: string,
  confidence: Finding['confidence'],
  observedAt: string
): Finding {
  const ruleId = `TLP-NPM-HEALTH-${signalId.toUpperCase()}`;
  const identity = `${observation.name}\0${observation.version}\0${observation.installPath}\0${signalId}`;
  const fingerprint = createHash('sha256').update(identity).digest('hex');
  const severity: FindingSeverity =
    signalId === 'new-install-script' ||
    signalId === 'repository-identity-changed'
      ? 'high'
      : signalId === 'stale-maintenance'
        ? 'low'
        : 'medium';
  return {
    id: `${ruleId}:${fingerprint}`,
    ruleId,
    title: ruleTitles[signalId] ?? 'Package health review signal',
    category: 'supply-chain',
    severity,
    confidence,
    message:
      'Public npm registry history contains a package maintenance or publisher signal that needs human review; it is not a compromise verdict.',
    source: 'npm-package-health',
    evidence: [{ summary: evidence.slice(0, 240), fingerprint }],
    remediation: {
      summary:
        'Review this exact installed package instance, its release history, registry provenance, and project change before updating or removing it.'
    },
    metadata: {
      ecosystem: 'npm',
      package: observation.name,
      installedVersion: observation.version,
      installPath: observation.installPath,
      registry: observation.health.registry,
      signalId,
      observedAt,
      publisherHistoryStatus: observation.health.publisherHistoryStatus,
      maintainerHistoryStatus: observation.health.maintainerHistoryStatus,
      releaseHistoryStatus: observation.health.releaseHistoryStatus
    }
  };
}

/**
 * Joins bounded npm registry history to exact resolved lockfile instances.
 * Provider work is O(U) lookups with bounded concurrency, where U is the
 * number of unique package/version/registry tuples; mapping findings back to
 * installed paths is O(I+F), where I is installed instances and F signals.
 */
export async function analyzePackageHealth(
  identities: DependencyIdentity[],
  options: PackageHealthAnalysisOptions = {}
): Promise<PackageHealthAnalysis> {
  const npmInstances = identities
    .filter((identity) => identity.ecosystem === 'npm')
    .map((identity) => ({
      name: identity.name,
      version: identity.version,
      installPath: identity.installPath,
      ...(identity.registry ? { registry: identity.registry } : {})
    }));
  const client =
    options.client ??
    new NpmPackageHealthClient({
      allowScopedPublicPackage: options.allowPublicScope === true,
      offline: options.offline === true,
      concurrency: options.concurrency,
      requestTimeoutMs: options.requestTimeoutMs
    });
  if (npmInstances.length > 1000) {
    return {
      coverage: coverageOf({
        eligible: npmInstances.length,
        scanned: 0,
        skipped: 0,
        failed: npmInstances.length
      }),
      observations: [],
      findings: [],
      warnings: ['package-health-batch-limit-exceeded']
    };
  }
  const observations = await client.inspectMany(npmInstances, options.signal);
  const available = observations.filter(
    (item) => item.health.status === 'available'
  ).length;
  const notQueried = observations.filter(
    (item) => item.health.status === 'not_queried'
  ).length;
  const failed = observations.length - available - notQueried;
  const warnings = [
    ...new Set(observations.flatMap((item) => item.health.warnings))
  ].sort();
  const findings = observations.flatMap((observation) =>
    observation.health.signals.map((signal) =>
      findingFor(
        observation,
        signal.id,
        signal.evidence,
        signal.confidence,
        signal.observedAt
      )
    )
  );
  return {
    coverage: coverageOf({
      eligible: npmInstances.length,
      scanned: available,
      skipped: notQueried,
      failed
    }),
    observations,
    findings,
    warnings
  };
}
