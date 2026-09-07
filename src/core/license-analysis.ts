import type { Finding } from '../contracts/finding.js';
import { DepsDevClient } from '../providers/depsdev/client.js';
import { readNpmDependencyInventory } from './dependencies/inventory.js';

export type LicenseEntry = {
  name: string;
  version: string;
  license: string;
  type: 'dependency' | 'devDependency';
  metadataSource: 'deps.dev' | 'unavailable';
  metadataError?: string;
};

export type LicenseAnalysisResult = {
  licenses: LicenseEntry[];
  findings: Finding[];
  warnings: string[];
  summary: {
    total: number;
    unknown: number;
    restrictive: number;
    distribution: Record<string, number>;
  };
};

export type LicenseMetadataProvider = Pick<DepsDevClient, 'getVersion'>;

export async function analyzeLicenses(
  root: string,
  provider: LicenseMetadataProvider = new DepsDevClient(),
  signal?: AbortSignal
): Promise<LicenseAnalysisResult> {
  const inventory = await readNpmDependencyInventory(root);
  const directDependencies = inventory.filter((dependency) => dependency.direct);

  const entries = await Promise.all(
    directDependencies.map(async (dependency): Promise<LicenseEntry> => {
      try {
        const metadata = await provider.getVersion(
          dependency.name,
          dependency.version,
          signal
        );
        const licenses = (metadata.licenses ?? [])
          .map((license) => license.trim())
          .filter(Boolean);

        return {
          name: dependency.name,
          version: dependency.version,
          license: licenses.length > 0 ? licenses.join(' OR ') : 'UNKNOWN',
          type: dependency.development ? 'devDependency' : 'dependency',
          metadataSource: 'deps.dev'
        };
      } catch (error) {
        return {
          name: dependency.name,
          version: dependency.version,
          license: 'UNKNOWN',
          type: dependency.development ? 'devDependency' : 'dependency',
          metadataSource: 'unavailable',
          metadataError: errorMessage(error)
        };
      }
    })
  );

  entries.sort((a, b) => a.name.localeCompare(b.name));

  const findings = entries.flatMap(licenseToFindings);
  const warnings = entries
    .filter((entry) => entry.metadataSource === 'unavailable')
    .map(
      (entry) =>
        `License metadata unavailable for ${entry.name}@${entry.version}: ${entry.metadataError ?? 'provider error'}`
    );
  const distribution = entries.reduce<Record<string, number>>((summary, entry) => {
    summary[entry.license] = (summary[entry.license] ?? 0) + 1;
    return summary;
  }, {});

  return {
    licenses: entries,
    findings,
    warnings,
    summary: {
      total: entries.length,
      unknown: entries.filter((entry) => entry.license === 'UNKNOWN').length,
      restrictive: entries.filter((entry) => isRestrictiveLicense(entry.license)).length,
      distribution
    }
  };
}

function isRestrictiveLicense(license: string): boolean {
  return /\b(?:AGPL|GPL|LGPL)(?:-\d+(?:\.\d+)?)?(?:-ONLY|-OR-LATER)?\b/i.test(
    license
  );
}

function licenseToFindings(entry: LicenseEntry): Finding[] {
  if (entry.license === 'UNKNOWN') {
    const providerUnavailable = entry.metadataSource === 'unavailable';

    return [
      licenseFinding(
        entry,
        providerUnavailable
          ? 'TOOLIP-LICENSE-METADATA-UNAVAILABLE'
          : 'TOOLIP-LICENSE-UNKNOWN',
        providerUnavailable
          ? `License metadata unavailable: ${entry.name}`
          : `Unknown license: ${entry.name}`,
        'medium',
        providerUnavailable
          ? `Toolip could not retrieve authoritative license metadata for ${entry.name}@${entry.version} from deps.dev.`
          : `deps.dev did not report a license for ${entry.name}@${entry.version}.`,
        providerUnavailable
          ? 'Retry when dependency metadata is available or verify the package license directly from its registry/repository before distribution.'
          : 'Verify the package license directly from its registry/repository before distribution.',
        providerUnavailable ? 'deps.dev metadata unavailable' : 'No license reported'
      )
    ];
  }

  if (isRestrictiveLicense(entry.license)) {
    return [
      licenseFinding(
        entry,
        'TOOLIP-LICENSE-RESTRICTIVE',
        `Restrictive license detected: ${entry.name}`,
        'high',
        `${entry.name}@${entry.version} reports ${entry.license} via deps.dev, which may introduce redistribution obligations.`,
        'Review the applicable license terms before using this package in proprietary or distributed software.',
        entry.license
      )
    ];
  }

  return [];
}

function licenseFinding(
  entry: LicenseEntry,
  ruleId: string,
  title: string,
  severity: Finding['severity'],
  message: string,
  recommendation: string,
  evidence: string
): Finding {
  return {
    id: `${ruleId}-${entry.name.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
    ruleId,
    title,
    severity,
    confidence: entry.metadataSource === 'deps.dev' ? 'high' : 'medium',
    category: 'license',
    message,
    source: 'license-analysis',
    evidence: [
      {
        summary: evidence,
        fingerprint: `${entry.name}:${entry.version}:${entry.license}:${entry.metadataSource}`
      }
    ],
    remediation: { summary: recommendation },
    metadata: { ...entry }
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
