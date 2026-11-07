import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { setImmediate as yieldToEventLoop } from 'node:timers/promises';
import {
  readNpmDependencyGraph,
  type DependencyFileSource,
  type DependencyIdentity
} from '../dependencies/inventory.js';
import { readOtherEcosystemInventoryDetailed } from '../dependencies/ecosystem-inventory.js';
import type { GoCommandRunner } from '../dependencies/go-module-graph.js';

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
  return `pkg:npm/${normalizedName}@${encodePurlComponent(version)}`;
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
      return `pkg:pypi/${encodeURIComponent(dependency.name.toLowerCase().replace(/[-_.]+/gu, '-'))}@${encodeURIComponent(dependency.version)}`;
    case 'Go':
      return `pkg:golang/${dependency.name.split('/').map(encodeURIComponent).join('/')}@${encodeURIComponent(dependency.version)}`;
    case 'crates.io':
      return `pkg:cargo/${encodeURIComponent(dependency.name)}@${encodeURIComponent(dependency.version)}`;
    case 'Maven': {
      const [group, artifact] = dependency.name.split(':');
      const base = `pkg:maven/${encodeURIComponent(group ?? '')}/${encodeURIComponent(artifact ?? dependency.name)}@${encodeURIComponent(dependency.version)}`;
      const qualifiers = [
        ...(dependency.classifier
          ? [`classifier=${encodeURIComponent(dependency.classifier)}`]
          : []),
        ...(dependency.packageType && dependency.packageType !== 'jar'
          ? [`type=${encodeURIComponent(dependency.packageType)}`]
          : [])
      ];
      return qualifiers.length > 0 ? `${base}?${qualifiers.join('&')}` : base;
    }
    case 'Packagist':
      return `pkg:composer/${dependency.name.split('/').map(encodeURIComponent).join('/')}@${encodeURIComponent(dependency.version)}`;
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
  const graphWarnings = [
    ...new Set([...graph.warnings, ...otherEcosystems.warnings])
  ].sort();
  const allEdges = [...graph.edges, ...otherEcosystems.edges];
  const graphComplete = graph.complete && otherEcosystems.complete;
  const graphDigest = createHash('sha256')
    .update(
      JSON.stringify({
        packages: dependencies.map((dependency) => dependency.id).sort(),
        edges: allEdges
          .map((edge) => [
            edge.from,
            edge.to,
            edge.name,
            edge.requirement,
            edge.section,
            edge.marker,
            edge.extras
          ])
          .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))
      })
    )
    .digest('hex');
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
          }
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
    await mapWithCancellation(dependencies, (dependency) => [
      dependency.id,
      spdxId(
        `${dependency.name}-${dependency.version}-${dependency.installPath}`
      )
    ] as const, options.signal)
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
      sourceInfo: `Toolip resolution confidence: ${dependency.resolutionConfidence ?? 'lockfile'}; source: ${dependency.source}`,
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
