import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { setImmediate as yieldToEventLoop } from 'node:timers/promises';
import { PackageURL } from 'packageurl-js';
import { mapConcurrent } from '../../application/concurrency.js';
import {
  readNpmDependencyGraph,
  type DependencyFileSource,
  type DependencyIdentity
} from '../dependencies/inventory.js';
import { digestDependencyGraph } from '../dependencies/graph-digest.js';
import { readOtherEcosystemInventoryDetailed } from '../dependencies/ecosystem-inventory.js';
import type { GoCommandRunner } from '../dependencies/go-module-graph.js';
import {
  npmProvenanceIdentityDigest,
  verifyNpmProvenance,
  type NpmProvenancePolicy,
  type NpmProvenanceVerification
} from '../../providers/npm/provenance.js';

export type SbomFormat = 'cyclonedx' | 'spdx';

type RootManifest = {
  name?: string;
  version?: string;
  description?: string;
  license?: string;
};

export function npmPurl(name: string, version: string): string {
  if (!version || /\s/u.test(version))
    throw new Error('npm package URL version is invalid.');
  const scoped = name.startsWith('@');
  const parts = scoped ? name.slice(1).split('/') : [name];
  if (
    (scoped && parts.length !== 2) ||
    (!scoped && name.includes('/')) ||
    parts.some((part) => !part || /[\\\s]/u.test(part))
  )
    throw new Error('npm package URL name is invalid.');
  const encoded = parts.map(encodePurlComponent);
  const normalizedName = scoped ? `%40${encoded[0]}/${encoded[1]}` : encoded[0];
  const value = `pkg:npm/${normalizedName}@${encodePurlComponent(version)}`;
  const parsed = PackageURL.fromString(value);
  if (
    parsed.type !== 'npm' ||
    parsed.namespace !== (scoped ? `@${parts[0]}` : undefined) ||
    parsed.name !== parts.at(-1) ||
    parsed.version !== version
  )
    throw new Error('npm package URL components did not round-trip.');
  return value;
}

function encodePurlComponent(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/gu,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

function purl(dependency: DependencyIdentity): string {
  switch (dependency.ecosystem) {
    case 'npm':
      return npmPurl(dependency.name, dependency.version);
    case 'PyPI':
      return new PackageURL(
        'pypi',
        undefined,
        dependency.name.toLowerCase().replace(/[-_.]+/gu, '-'),
        dependency.version
      ).toString();
    case 'Go':
      return `pkg:golang/${dependency.name.split('/').map(encodeURIComponent).join('/')}@${encodeURIComponent(dependency.version)}`;
    case 'crates.io':
      return new PackageURL(
        'cargo',
        undefined,
        dependency.name,
        dependency.version
      ).toString();
    case 'Maven': {
      const [group, artifact] = dependency.name.split(':');
      return new PackageURL(
        'maven',
        group ?? '',
        artifact ?? dependency.name,
        dependency.version,
        {
          ...(dependency.classifier
            ? { classifier: dependency.classifier }
            : {}),
          ...(dependency.packageType && dependency.packageType !== 'jar'
            ? { type: dependency.packageType }
            : {})
        }
      ).toString();
    }
    case 'Packagist': {
      const [namespace, name] = dependency.name.split('/');
      if (!namespace || !name || dependency.name.split('/').length !== 2)
        throw new Error('Composer package name is invalid.');
      return new PackageURL(
        'composer',
        namespace,
        name,
        dependency.version
      ).toString();
    }
  }
}

function stableRef(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 24);
}

function bomRef(dependency: DependencyIdentity): string {
  return `urn:toolip:${dependency.ecosystem}:${stableRef(dependency.id)}`;
}

function spdxId(value: string): string {
  return `SPDXRef-${value.replaceAll(/[^A-Za-z0-9.-]/g, '-')}`;
}

function namespace(name: string, version: string, graphDigest: string): string {
  const digest = createHash('sha256')
    .update(`${name}@${version}:${graphDigest}`)
    .digest('hex')
    .slice(0, 24);

  return `https://toolip.dev/spdx/${encodeURIComponent(
    name
  )}/${version}/${digest}`;
}

function hasValidStrongSri(value: string): boolean {
  return value.split(/\s+/u).some((part) => {
    const match = /^(sha512|sha384|sha256)-([A-Za-z0-9+/]+={0,2})$/u.exec(part);
    if (!match) return false;
    const algorithm = match[1];
    const encoded = match[2];
    if (!algorithm || !encoded) return false;
    const digest = Buffer.from(encoded, 'base64');
    const expectedBytes =
      algorithm === 'sha512' ? 64 : algorithm === 'sha384' ? 48 : 32;
    return (
      digest.length === expectedBytes && digest.toString('base64') === encoded
    );
  });
}

function artifactIntegrityStatus(
  dependency: DependencyIdentity,
  verification?: NpmProvenanceVerification
): 'verified' | 'declared-not-verified' | 'unknown' | 'mismatch' {
  if (dependency.ecosystem === 'npm' && verification)
    return verification.artifactIntegrity;
  const integrity = dependency.integrity;
  if (!integrity) return 'unknown';
  if (
    dependency.ecosystem === 'Go' &&
    dependency.source === 'go-tool:mvs-sumdb-verified' &&
    /^h1:[A-Za-z0-9+/]{43}=$/u.test(integrity)
  )
    return 'verified';
  if (
    (dependency.ecosystem === 'npm' && hasValidStrongSri(integrity)) ||
    (dependency.ecosystem === 'crates.io' &&
      /^[a-f0-9]{64}$/iu.test(integrity)) ||
    (dependency.ecosystem === 'Go' &&
      /^h1:[A-Za-z0-9+/]{43}=$/u.test(integrity))
  )
    return 'declared-not-verified';
  return 'unknown';
}

function provenanceProperties(
  dependency: DependencyIdentity,
  verification?: NpmProvenanceVerification
) {
  const publisherTrustStatus =
    verification?.status === 'verified'
      ? 'verified'
      : verification && ['untrusted', 'invalid'].includes(verification.status)
        ? 'untrusted'
        : 'unknown';
  return [
    {
      name: 'toolip:artifactIntegrityStatus',
      value: artifactIntegrityStatus(dependency, verification)
    },
    { name: 'toolip:publisherTrustStatus', value: publisherTrustStatus },
    { name: 'toolip:codeSafetyStatus', value: 'not-asserted' },
    ...(verification
      ? [
          {
            name: 'toolip:provenanceVerificationStatus',
            value: verification.status
          },
          {
            name: 'toolip:provenanceVerificationReason',
            value: verification.reason
          },
          ...(verification.sourceRepository
            ? [
                {
                  name: 'toolip:verifiedSourceRepository',
                  value: verification.sourceRepository
                },
                {
                  name: 'toolip:verifiedCertificateIssuer',
                  value: verification.certificateIssuer ?? ''
                },
                {
                  name: 'toolip:verifiedCertificateIdentity',
                  value: verification.certificateIdentity ?? ''
                }
              ]
            : [])
        ]
      : []),
    ...(dependency.registry
      ? [{ name: 'toolip:registryOrigin', value: dependency.registry }]
      : []),
    ...(dependency.integrity
      ? [{ name: 'toolip:declaredIntegrity', value: dependency.integrity }]
      : [])
  ];
}

function spdxSourceInfo(
  dependency: DependencyIdentity,
  verification?: NpmProvenanceVerification
): string {
  return [
    `Toolip resolution confidence: ${dependency.resolutionConfidence ?? 'lockfile'}`,
    `source: ${dependency.source}`,
    `artifact integrity: ${artifactIntegrityStatus(dependency, verification)}`,
    `publisher trust: ${verification?.status === 'verified' ? 'verified' : verification && ['untrusted', 'invalid'].includes(verification.status) ? 'untrusted' : 'unknown'}`,
    'code safety: not asserted',
    ...(verification
      ? [
          `provenance verification: ${verification.status} (${verification.reason})`
        ]
      : []),
    ...(verification?.sourceRepository
      ? [`verified source repository: ${verification.sourceRepository}`]
      : []),
    ...(dependency.registry ? [`registry: ${dependency.registry}`] : []),
    ...(dependency.integrity
      ? [`declared integrity: ${dependency.integrity}`]
      : [])
  ].join('; ');
}

/** SPDX 2.3's timestamp grammar accepts whole-second UTC values only. */
function spdxTimestamp(now = new Date()): string {
  return now.toISOString().replace(/\.\d{3}Z$/u, 'Z');
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  const error = new Error('SBOM generation was cancelled.');
  error.name = 'AbortError';
  throw error;
}

async function mapWithCancellation<T, R>(
  values: readonly T[],
  mapper: (value: T) => R,
  signal?: AbortSignal
): Promise<R[]> {
  const result: R[] = [];
  for (let index = 0; index < values.length; index++) {
    if (index > 0 && index % 256 === 0) {
      throwIfAborted(signal);
      await yieldToEventLoop(undefined, { signal });
    }
    throwIfAborted(signal);
    result.push(mapper(values[index] as T));
  }
  throwIfAborted(signal);
  return result;
}

export async function generateSbom(
  root: string,
  format: SbomFormat,
  options: {
    fileSource?: DependencyFileSource;
    allowGoToolExecution?: boolean;
    goCommandRunner?: GoCommandRunner;
    signal?: AbortSignal;
    npmProvenancePolicy?: NpmProvenancePolicy;
    allowPublicScope?: boolean;
    npmProvenanceVerifier?: typeof verifyNpmProvenance;
  } = {}
): Promise<Record<string, unknown>> {
  throwIfAborted(options.signal);
  let manifest: RootManifest = {};
  const manifestPath = 'package.json';
  if (options.fileSource) {
    const captured = options.fileSource.readText(manifestPath);
    if (captured !== undefined) manifest = JSON.parse(captured) as RootManifest;
    else if (options.fileSource.hasFile(manifestPath))
      throw new Error(
        'Root package manifest is unavailable in the bounded snapshot.'
      );
  } else {
    try {
      manifest = JSON.parse(
        await readFile(path.join(root, manifestPath), 'utf8')
      ) as RootManifest;
    } catch (error) {
      if (
        !error ||
        typeof error !== 'object' ||
        !('code' in error) ||
        error.code !== 'ENOENT'
      )
        throw error;
    }
  }

  let graph: Awaited<ReturnType<typeof readNpmDependencyGraph>> = {
    packages: [],
    edges: [],
    unresolvedDependencies: [],
    rootDependencies: [],
    complete: false,
    warnings: ['No supported npm package-manager lockfile was found.']
  };
  try {
    graph = await readNpmDependencyGraph(root, options.fileSource);
  } catch (error) {
    if (
      !error ||
      typeof error !== 'object' ||
      !('code' in error) ||
      error.code !== 'ENOENT'
    )
      throw error;
  }
  throwIfAborted(options.signal);
  const otherEcosystems = await readOtherEcosystemInventoryDetailed(
    root,
    options.fileSource,
    {
      allowGoToolExecution: options.allowGoToolExecution,
      goCommandRunner: options.goCommandRunner
    }
  );
  throwIfAborted(options.signal);
  const dependencies = [...graph.packages, ...otherEcosystems.packages].sort(
    (a, b) => a.id.localeCompare(b.id)
  );
  const npmProvenance = new Map<string, NpmProvenanceVerification>();
  if (options.npmProvenancePolicy) {
    const candidates = new Map<string, DependencyIdentity>();
    for (const dependency of dependencies) {
      if (dependency.ecosystem !== 'npm') continue;
      candidates.set(npmProvenanceIdentityDigest(dependency), dependency);
    }
    const verifier = options.npmProvenanceVerifier ?? verifyNpmProvenance;
    const verifications = await mapConcurrent(
      [...candidates.values()],
      8,
      (dependency) =>
        verifier(dependency, {
          policy: options.npmProvenancePolicy,
          allowPublicScope: options.allowPublicScope,
          requestTimeoutMs: 5000,
          signal: options.signal
        })
    );
    for (const verification of verifications) {
      npmProvenance.set(verification.identityDigest, verification);
    }
  }
  const graphWarnings = [
    ...new Set([...graph.warnings, ...otherEcosystems.warnings])
  ].sort();
  const allEdges = [...graph.edges, ...otherEcosystems.edges];
  const graphComplete = graph.complete && otherEcosystems.complete;
  const graphDigest = digestDependencyGraph({
    manager: graph.manager,
    complete: graphComplete,
    packages: dependencies,
    edges: allEdges,
    unresolvedDependencies: graph.unresolvedDependencies,
    warnings: graphWarnings
  });
  const byId = new Map(
    dependencies.map((dependency) => [dependency.id, dependency])
  );

  const rootName =
    manifest.name ?? path.basename(path.resolve(root)) ?? 'unknown-project';
  const rootVersion = manifest.version ?? '0.0.0';
  const rootRef = `urn:toolip:root:${stableRef(`${rootName}@${rootVersion}`)}`;

  if (format === 'cyclonedx') {
    const dependsOn = new Map<string, Set<string>>();

    for (let index = 0; index < allEdges.length; index++) {
      if (index > 0 && index % 256 === 0) {
        throwIfAborted(options.signal);
        await yieldToEventLoop(undefined, { signal: options.signal });
      }
      const edge = allEdges[index];
      throwIfAborted(options.signal);
      if (!edge) continue;
      const fromNode = edge.from === 'root' ? undefined : byId.get(edge.from);
      const from =
        edge.from === 'root'
          ? rootRef
          : fromNode
            ? bomRef(fromNode)
            : undefined;
      const target = byId.get(edge.to);
      if (!from || !target) continue;

      const current = dependsOn.get(from) ?? new Set<string>();
      const targetRef = bomRef(target);
      current.add(targetRef);
      dependsOn.set(from, current);
    }

    const components = await mapWithCancellation(
      dependencies,
      (dependency) => ({
        type: 'library',
        'bom-ref': bomRef(dependency),
        name: dependency.name,
        version: dependency.version,
        scope: dependency.development ? 'optional' : 'required',
        purl: purl(dependency),
        properties: [
          {
            name: 'toolip:direct',
            value: String(dependency.direct)
          },
          {
            name: 'toolip:development',
            value: String(dependency.development)
          },
          {
            name: 'toolip:resolutionConfidence',
            value: dependency.resolutionConfidence ?? 'lockfile'
          },
          {
            name: 'toolip:installPath',
            value: dependency.installPath
          },
          ...provenanceProperties(
            dependency,
            npmProvenance.get(npmProvenanceIdentityDigest(dependency))
          )
        ]
      }),
      options.signal
    );
    const dependencyEntries = await mapWithCancellation(
      dependencies,
      (dependency) => {
        const ref = bomRef(dependency);
        return {
          ref,
          dependsOn: [...(dependsOn.get(ref) ?? new Set())].sort()
        };
      },
      options.signal
    );
    const rootDependencies = {
      ref: rootRef,
      dependsOn: [...(dependsOn.get(rootRef) ?? new Set())].sort()
    };

    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [
          {
            vendor: 'Toolip',
            name: 'toolip'
          }
        ],
        properties: [
          {
            name: 'toolip:dependencyGraphComplete',
            value: String(graphComplete)
          },
          ...graphWarnings.slice(0, 20).map((warning) => ({
            name: 'toolip:dependencyGraphWarning',
            value: warning
          }))
        ],
        component: {
          type: 'application',
          'bom-ref': rootRef,
          name: rootName,
          version: rootVersion,
          description: manifest.description
        }
      },
      components,
      dependencies: [rootDependencies, ...dependencyEntries]
    };
  }

  const documentId = 'SPDXRef-DOCUMENT';
  const rootId = spdxId(`${rootName}-${rootVersion}`);
  const packageSpdxIds = new Map(
    await mapWithCancellation(
      dependencies,
      (dependency) =>
        [
          dependency.id,
          spdxId(
            `${dependency.name}-${dependency.version}-${dependency.installPath}`
          )
        ] as const,
      options.signal
    )
  );
  const packages = await mapWithCancellation(
    dependencies,
    (dependency) => ({
      name: dependency.name,
      SPDXID: packageSpdxIds.get(dependency.id),
      versionInfo: dependency.version,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      sourceInfo: spdxSourceInfo(
        dependency,
        npmProvenance.get(npmProvenanceIdentityDigest(dependency))
      ),
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: purl(dependency)
        }
      ]
    }),
    options.signal
  );
  const relationships = await mapWithCancellation(
    allEdges,
    (edge) => {
      const relatedSpdxElement = packageSpdxIds.get(edge.to);
      if (!relatedSpdxElement) return undefined;

      const spdxElementId =
        edge.from === 'root' ? rootId : packageSpdxIds.get(edge.from);
      if (!spdxElementId) return undefined;

      return {
        spdxElementId,
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement
      };
    },
    options.signal
  );

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: documentId,
    name: `${rootName}-${rootVersion}`,
    documentNamespace: namespace(rootName, rootVersion, graphDigest),
    creationInfo: {
      created: spdxTimestamp(),
      creators: ['Tool: Toolip'],
      comment: graphComplete
        ? 'Toolip dependency graph is complete for the supported lockfiles discovered.'
        : `Toolip dependency graph is incomplete: ${graphWarnings.slice(0, 5).join('; ')}`
    },
    packages: [
      {
        name: rootName,
        SPDXID: rootId,
        versionInfo: rootVersion,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: manifest.license ?? 'NOASSERTION',
        licenseDeclared: manifest.license ?? 'NOASSERTION'
      },
      ...packages
    ],
    relationships: relationships.filter(
      (relationship): relationship is NonNullable<typeof relationship> =>
        relationship !== undefined
    )
  };
}
