import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  readNpmDependencyGraph,
  type DependencyIdentity
} from '../dependencies/inventory.js';

export type SbomFormat =
  | 'cyclonedx'
  | 'spdx';

type RootManifest = {
  name?: string;
  version?: string;
  description?: string;
  license?: string;
};

function purl(
  dependency: DependencyIdentity
): string {
  return (
    `pkg:npm/${encodeURIComponent(
      dependency.name
    )}@${encodeURIComponent(dependency.version)}`
  );
}

function stableRef(value: string): string {
  return createHash('sha256')
    .update(value)
    .digest('hex')
    .slice(0, 24);
}

function bomRef(
  dependency: DependencyIdentity
): string {
  return `urn:toolip:npm:${stableRef(dependency.id)}`;
}

function spdxId(value: string): string {
  return (
    'SPDXRef-' +
    value.replaceAll(/[^A-Za-z0-9.-]/g, '-')
  );
}

function namespace(
  name: string,
  version: string
): string {
  const digest = createHash('sha256')
    .update(`${name}@${version}:${Date.now()}`)
    .digest('hex')
    .slice(0, 24);

  return `https://toolip.dev/spdx/${encodeURIComponent(
    name
  )}/${version}/${digest}`;
}

export async function generateSbom(
  root: string,
  format: SbomFormat
): Promise<Record<string, unknown>> {
  const manifest = JSON.parse(
    await readFile(
      path.join(root, 'package.json'),
      'utf8'
    )
  ) as RootManifest;

  const graph = await readNpmDependencyGraph(root);
  const dependencies = graph.packages;
  const byId = new Map(
    dependencies.map((dependency) => [dependency.id, dependency])
  );

  const rootName = manifest.name ?? 'unknown-project';
  const rootVersion = manifest.version ?? '0.0.0';
  const rootRef = `urn:toolip:root:${stableRef(`${rootName}@${rootVersion}`)}`;

  if (format === 'cyclonedx') {
    const dependsOn = new Map<string, string[]>();

    for (const edge of graph.edges) {
      const from = edge.from === 'root'
        ? rootRef
        : byId.get(edge.from)
          ? bomRef(byId.get(edge.from)!)
          : undefined;
      const target = byId.get(edge.to);
      if (!from || !target) continue;

      const current = dependsOn.get(from) ?? [];
      const targetRef = bomRef(target);
      if (!current.includes(targetRef)) current.push(targetRef);
      dependsOn.set(from, current);
    }

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
        component: {
          type: 'application',
          'bom-ref': rootRef,
          name: rootName,
          version: rootVersion,
          description: manifest.description
        }
      },
      components: dependencies.map((dependency) => ({
        type: 'library',
        'bom-ref': bomRef(dependency),
        name: dependency.name,
        version: dependency.version,
        scope: dependency.development
          ? 'optional'
          : 'required',
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
            name: 'toolip:installPath',
            value: dependency.installPath
          }
        ]
      })),
      dependencies: [
        {
          ref: rootRef,
          dependsOn: dependsOn.get(rootRef) ?? []
        },
        ...dependencies.map((dependency) => {
          const ref = bomRef(dependency);
          return {
            ref,
            dependsOn: dependsOn.get(ref) ?? []
          };
        })
      ]
    };
  }

  const documentId = 'SPDXRef-DOCUMENT';
  const rootId = spdxId(
    `${rootName}-${rootVersion}`
  );
  const packageSpdxIds = new Map(
    dependencies.map((dependency) => [
      dependency.id,
      spdxId(`${dependency.name}-${dependency.version}-${dependency.installPath}`)
    ])
  );

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: documentId,
    name: `${rootName}-${rootVersion}`,
    documentNamespace: namespace(
      rootName,
      rootVersion
    ),
    creationInfo: {
      created: new Date().toISOString(),
      creators: ['Tool: Toolip']
    },
    packages: [
      {
        name: rootName,
        SPDXID: rootId,
        versionInfo: rootVersion,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded:
          manifest.license ?? 'NOASSERTION',
        licenseDeclared:
          manifest.license ?? 'NOASSERTION'
      },
      ...dependencies.map((dependency) => ({
        name: dependency.name,
        SPDXID: packageSpdxIds.get(dependency.id),
        versionInfo: dependency.version,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: purl(dependency)
          }
        ]
      }))
    ],
    relationships: graph.edges.flatMap((edge) => {
      const relatedSpdxElement = packageSpdxIds.get(edge.to);
      if (!relatedSpdxElement) return [];

      const spdxElementId = edge.from === 'root'
        ? rootId
        : packageSpdxIds.get(edge.from);
      if (!spdxElementId) return [];

      return [{
        spdxElementId,
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement
      }];
    })
  };
}
