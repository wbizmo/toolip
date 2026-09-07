import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Finding } from '../contracts/finding.js';

export type LicenseEntry = {
  name: string;
  version: string;
  license: string;
  type: 'dependency' | 'devDependency';
};

export type LicenseAnalysisResult = {
  licenses: LicenseEntry[];
  findings: Finding[];
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

function licenseToFindings(entry: LicenseEntry): Finding[] {
  if (entry.license === 'UNKNOWN') {
    return [licenseFinding(
      entry,
      'TOOLIP-LICENSE-UNKNOWN',
      `Unknown license: ${entry.name}`,
      'medium',
      `${entry.name} does not have a known license in Toolip's local license intelligence map.`,
      'Manually verify the package license before using it in commercial or distributed software.',
      entry.version
    )];
  }

  if (restrictiveLicenses.has(entry.license)) {
    return [licenseFinding(
      entry,
      'TOOLIP-LICENSE-RESTRICTIVE',
      `Restrictive license detected: ${entry.name}`,
      'high',
      `${entry.name} appears to use ${entry.license}, which may introduce redistribution obligations.`,
      'Review the license terms with care before using this package in proprietary software.',
      entry.license
    )];
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
    confidence: 'medium',
    category: 'license',
    message,
    source: 'license-analysis',
    evidence: [{
      summary: evidence,
      fingerprint: `${entry.name}:${entry.version}:${entry.license}`
    }],
    remediation: { summary: recommendation },
    metadata: { ...entry }
  };
}
