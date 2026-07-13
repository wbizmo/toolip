import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import type { Finding } from '../../contracts/finding.js';

type PackageManifest = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

export type RegistryLookup = (
  packageName: string,
  signal?: AbortSignal
) => Promise<boolean>;

function dependencies(
  manifest: PackageManifest
): Array<{
  name: string;
  requirement: string;
  section: string;
}> {
  const sections = [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies'
  ] as const;

  const output: Array<{
    name: string;
    requirement: string;
    section: string;
  }> = [];

  for (const section of sections) {
    for (const [name, requirement] of Object.entries(
      manifest[section] ?? {}
    )) {
      output.push({
        name,
        requirement,
        section
      });
    }
  }

  return output;
}

function internalSignal(
  name: string,
  requirement: string
): boolean {
  return (
    requirement.startsWith('file:') ||
    requirement.startsWith('workspace:') ||
    requirement.startsWith('link:') ||
    requirement.startsWith('git+') ||
    requirement.startsWith('github:') ||
    (
      name.startsWith('@') &&
      (
        requirement === '*' ||
        requirement === 'latest'
      )
    )
  );
}

async function defaultLookup(
  packageName: string,
  signal?: AbortSignal
): Promise<boolean> {
  const response = await fetch(
    `https://registry.npmjs.org/${encodeURIComponent(
      packageName
    )}`,
    {
      method: 'HEAD',
      headers: {
        'user-agent': 'toolip'
      },
      signal
    }
  );

  if (response.status === 404) {
    return false;
  }

  if (!response.ok) {
    throw new Error(
      `npm registry lookup failed with HTTP ${response.status}.`
    );
  }

  return true;
}

export class DependencyConfusionAnalyzer
  implements Analyzer
{
  readonly id = 'dependency-confusion';
  readonly version = '1.0.0';

  constructor(
    private readonly lookup: RegistryLookup =
      defaultLookup
  ) {}

  async analyze(
    context: AnalyzerContext
  ): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const manifest = JSON.parse(
      await readFile(
        path.join(context.root, 'package.json'),
        'utf8'
      )
    ) as PackageManifest;

    const candidates =
      dependencies(manifest).filter((item) =>
        internalSignal(
          item.name,
          item.requirement
        )
      );

    const findings: Finding[] = [];

    for (const candidate of candidates) {
      const existsPublicly =
        await this.lookup(
          candidate.name,
          context.signal
        );

      if (!existsPublicly) {
        continue;
      }

      findings.push({
        id:
          `TLP-CONFUSION-001:${candidate.name}`,
        ruleId: 'TLP-CONFUSION-001',
        title:
          `Internal dependency name exists publicly: ${candidate.name}`,
        category: 'dependency-confusion',
        severity: 'high',
        confidence: 'medium',
        message:
          `${candidate.name} uses ${candidate.requirement} in ` +
          `${candidate.section}, but the same name exists on the public npm registry.`,
        source: 'npm-registry',
        evidence: [
          {
            summary:
              `${candidate.section}: ${candidate.name} = ${candidate.requirement}`,
            fingerprint:
              `${candidate.name}:${candidate.requirement}`
          }
        ],
        remediation: {
          summary:
            'Use an organization-controlled scope, enforce a private registry for the scope, pin registry configuration, and verify package provenance.'
        },
        metadata: candidate
      });
    }

    return {
      analyzer: this.id,
      durationMs: Math.round(
        performance.now() - startedAt
      ),
      findings,
      metadata: {
        candidates: candidates.length,
        publicCollisions: findings.length
      }
    };
  }
}
