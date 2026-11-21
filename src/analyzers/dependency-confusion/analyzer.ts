import path from 'node:path';
import { mapConcurrent } from '../../application/concurrency.js';
import { coverageOf } from '../../contracts/analysis.js';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import type { Finding } from '../../contracts/finding.js';
import { TextFileReader } from '../../core/text-file-reader.js';

type PackageManifest = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

type Candidate = {
  name: string;
  requirement: string;
  section: string;
};

const maximumManifestBytes = 2 * 1024 * 1024;
const maximumCandidateLookups = 5_000;
const maximumPackageNameBytes = 214;
const maximumRequirementBytes = 16 * 1024;

export type RegistryLookup = (
  packageName: string,
  signal?: AbortSignal
) => Promise<boolean>;

function dependencyCandidates(
  manifest: PackageManifest,
  maximum: number
): { candidates: Candidate[]; total: number; rejected: number } {
  const sections = [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies'
  ] as const;

  const candidates: Candidate[] = [];
  let total = 0;
  let rejected = 0;
  for (const section of sections) {
    const dependencies = manifest[section];
    if (dependencies === undefined) continue;
    if (
      dependencies === null ||
      typeof dependencies !== 'object' ||
      Array.isArray(dependencies)
    ) {
      throw new Error(`package.json ${section} must be an object`);
    }
    for (const name in dependencies) {
      if (!Object.hasOwn(dependencies, name)) continue;
      const requirement = dependencies[name];
      if (typeof requirement !== 'string')
        throw new Error(`package.json ${section} entries must be strings`);
      if (!internalSignal(name, requirement)) continue;
      total += 1;
      if (
        Buffer.byteLength(name, 'utf8') > maximumPackageNameBytes ||
        Buffer.byteLength(requirement, 'utf8') > maximumRequirementBytes
      ) {
        rejected += 1;
        continue;
      }
      if (candidates.length < maximum)
        candidates.push({ name, requirement, section });
    }
  }
  return { candidates, total, rejected };
}

function internalSignal(name: string, requirement: string): boolean {
  return (
    requirement.startsWith('file:') ||
    requirement.startsWith('workspace:') ||
    requirement.startsWith('link:') ||
    requirement.startsWith('git+') ||
    requirement.startsWith('github:') ||
    (name.startsWith('@') && (requirement === '*' || requirement === 'latest'))
  );
}

async function defaultLookup(
  packageName: string,
  signal?: AbortSignal
): Promise<boolean> {
  const response = await fetch(
    `https://registry.npmjs.org/${encodeURIComponent(packageName)}`,
    {
      method: 'HEAD',
      headers: { 'user-agent': 'toolip' },
      signal
    }
  );

  if (response.status === 404) return false;

  if (!response.ok) {
    throw new Error(`npm registry lookup failed with HTTP ${response.status}.`);
  }

  return true;
}

function toFinding(candidate: Candidate): Finding {
  return {
    id: `TLP-CONFUSION-001:${candidate.name}`,
    ruleId: 'TLP-CONFUSION-001',
    title: `Internal dependency name exists publicly: ${candidate.name}`,
    category: 'dependency-confusion',
    severity: 'high',
    confidence: 'medium',
    message:
      `${candidate.name} uses ${candidate.requirement} in ` +
      `${candidate.section}, but the same name exists on the public npm registry.`,
    source: 'npm-registry',
    evidence: [
      {
        summary: `${candidate.section}: ${candidate.name} = ${candidate.requirement}`,
        fingerprint: `${candidate.name}:${candidate.requirement}`
      }
    ],
    remediation: {
      summary:
        'Use an organization-controlled scope, enforce a private registry for the scope, pin registry configuration, and verify package provenance.'
    },
    metadata: candidate
  };
}

export class DependencyConfusionAnalyzer implements Analyzer {
  readonly id = 'dependency-confusion';
  readonly version = '1.0.1';

  constructor(
    private readonly lookup: RegistryLookup = defaultLookup,
    private readonly concurrency = 8
  ) {}

  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const manifestReader = new TextFileReader(
      {
        maxFiles: 1,
        maxFileBytes: maximumManifestBytes,
        maxTotalBytes: maximumManifestBytes
      },
      { root: context.root, maxConcurrentReads: 1 }
    );
    const manifestRead = await manifestReader.read(
      path.join(context.root, 'package.json'),
      context.signal
    );
    if (manifestRead.status !== 'ok') {
      const failed =
        manifestRead.status === 'failed' || manifestRead.status === 'changed';
      const reason =
        manifestRead.status === 'oversized'
          ? 'package.json exceeds the 2 MiB analysis limit'
          : manifestRead.status === 'cancelled'
            ? 'analysis was cancelled while reading package.json'
            : manifestRead.status === 'budget-exceeded'
              ? 'package.json exceeded the configured read budget'
              : manifestRead.status === 'binary'
                ? 'package.json is not valid text input'
                : 'package.json could not be read as a stable file';
      return {
        analyzer: this.id,
        durationMs: Math.round(performance.now() - startedAt),
        findings: [],
        warnings: [reason],
        coverage: coverageOf({
          eligible: 1,
          scanned: 0,
          skipped: failed ? 0 : 1,
          failed: failed ? 1 : 0,
          cancelled: manifestRead.status === 'cancelled'
        }),
        metadata: { candidates: 0, publicCollisions: 0 }
      };
    }

    let discovered: {
      candidates: Candidate[];
      total: number;
      rejected: number;
    };
    try {
      const manifest = JSON.parse(manifestRead.content) as PackageManifest;
      if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest))
        throw new Error('package.json root must be an object');
      discovered = dependencyCandidates(manifest, maximumCandidateLookups);
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : 'package.json is invalid';
      return {
        analyzer: this.id,
        durationMs: Math.round(performance.now() - startedAt),
        findings: [],
        warnings: [`Dependency confusion analysis failed: ${reason}.`],
        coverage: coverageOf({
          eligible: 1,
          scanned: 0,
          skipped: 0,
          failed: 1
        }),
        metadata: { candidates: 0, publicCollisions: 0 }
      };
    }
    const { candidates, total, rejected } = discovered;

    const checks = await mapConcurrent(
      candidates,
      this.concurrency,
      async (candidate) => ({
        candidate,
        existsPublicly: await this.lookup(candidate.name, context.signal)
      })
    );

    const findings = checks
      .filter((check) => check.existsPublicly)
      .map((check) => toFinding(check.candidate));

    return {
      analyzer: this.id,
      durationMs: Math.round(performance.now() - startedAt),
      findings,
      ...(total > candidates.length
        ? {
            warnings: [
              `Dependency confusion lookup budget or input limits withheld ${total - candidates.length} candidate(s).`
            ]
          }
        : {}),
      coverage: coverageOf({
        eligible: total,
        scanned: checks.length,
        skipped: total - checks.length,
        failed: 0
      }),
      metadata: {
        candidates: total,
        checkedCandidates: checks.length,
        rejectedCandidates: rejected,
        publicCollisions: findings.length
      }
    };
  }
}
