import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  readNpmDependencyInventory,
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

function bomRef(
  dependency: DependencyIdentity
): string {
  return purl(dependency);
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

  const dependencies =
    await readNpmDependencyInventory(root);

  const rootName = manifest.name ?? 'unknown-project';
  const rootVersion = manifest.version ?? '0.0.0';

  if (format === 'cyclonedx') {
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
          }
        ]
      })),
      dependencies: dependencies.map((dependency) => ({
        ref: bomRef(dependency),
        dependsOn: []
      }))
    };
  }

  const documentId = 'SPDXRef-DOCUMENT';
  const rootId = spdxId(
    `${rootName}-${rootVersion}`
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
        SPDXID: spdxId(
          `${dependency.name}-${dependency.version}`
        ),
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
    relationships: dependencies.map((dependency) => ({
      spdxElementId: rootId,
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement:
        spdxId(
          `${dependency.name}-${dependency.version}`
        )
    }))
  };
}
