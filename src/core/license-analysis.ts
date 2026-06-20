import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { ToolipFinding } from './report.js';

export type LicenseEntry = {
  name: string;
  version: string;
  license: string;
  type: 'dependency' | 'devDependency';
};

export type LicenseAnalysisResult = {
  licenses: LicenseEntry[];
  findings: ToolipFinding[];
  summary: {
    total: number;
    unknown: number;
    restrictive: number;
    distribution: Record<string, number>;
  };
};

const restrictiveLicenses = new Set([
  'GPL',
  'GPL-2.0',
  'GPL-3.0',
  'AGPL',
  'AGPL-3.0',
  'LGPL',
  'LGPL-2.1',
  'LGPL-3.0'
]);

export async function analyzeLicenses(root: string): Promise<LicenseAnalysisResult> {
  const packageJsonPath = path.join(root, 'package.json');
  const raw = await readFile(packageJsonPath, 'utf8');

  const pkg = JSON.parse(raw) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  const entries: LicenseEntry[] = [
    ...Object.entries(pkg.dependencies ?? {}).map(([name, version]) => ({
      name,
      version,
      license: inferLicense(name),
      type: 'dependency' as const
    })),
    ...Object.entries(pkg.devDependencies ?? {}).map(([name, version]) => ({
      name,
      version,
      license: inferLicense(name),
      type: 'devDependency' as const
    }))
  ].sort((a, b) => a.name.localeCompare(b.name));

  const findings = entries.flatMap(licenseToFindings);
  const distribution = entries.reduce<Record<string, number>>((summary, entry) => {
    summary[entry.license] = (summary[entry.license] ?? 0) + 1;
    return summary;
  }, {});

  return {
    licenses: entries,
    findings,
    summary: {
      total: entries.length,
      unknown: entries.filter((entry) => entry.license === 'UNKNOWN').length,
      restrictive: entries.filter((entry) => restrictiveLicenses.has(entry.license)).length,
      distribution
    }
  };
}

function inferLicense(packageName: string): string {
  const known: Record<string, string> = {
    '@types/node': 'MIT',
    '@types/semver': 'MIT',
    axios: 'MIT',
    chalk: 'MIT',
    commander: 'MIT',
    express: 'MIT',
    'fast-glob': 'MIT',
    ignore: 'MIT',
    ora: 'MIT',
    pacote: 'ISC',
    react: 'MIT',
    request: 'Apache-2.0',
    semver: 'ISC',
    tsx: 'MIT',
    typescript: 'Apache-2.0',
    vitest: 'MIT',
    zod: 'MIT'
  };

  return known[packageName] ?? 'UNKNOWN';
}

function licenseToFindings(entry: LicenseEntry): ToolipFinding[] {
  if (entry.license === 'UNKNOWN') {
    return [
      {
        id: `TOOLIP-LICENSE-UNKNOWN-${entry.name.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
        title: `Unknown license: ${entry.name}`,
        severity: 'medium',
        category: 'license',
        message: `${entry.name} does not have a known license in Toolip's local license intelligence map.`,
        recommendation: 'Manually verify the package license before using it in commercial or distributed software.',
        evidence: entry.version
      }
    ];
  }

  if (restrictiveLicenses.has(entry.license)) {
    return [
      {
        id: `TOOLIP-LICENSE-RESTRICTIVE-${entry.name.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
        title: `Restrictive license detected: ${entry.name}`,
        severity: 'high',
        category: 'license',
        message: `${entry.name} appears to use ${entry.license}, which may introduce redistribution obligations.`,
        recommendation: 'Review the license terms with care before using this package in proprietary software.',
        evidence: entry.license
      }
    ];
  }

  return [];
}
