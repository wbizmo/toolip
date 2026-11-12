import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { PackageURL } from 'packageurl-js';
import Ajv2019 from 'ajv/dist/2019.js';
import addFormats from 'ajv-formats';
import {
  Validation as CycloneDxValidation,
  Spec as CycloneDxSpec
} from '@cyclonedx/cyclonedx-library';
import { generateSbom } from '../../src/core/sbom/generate.js';
import { npmPurl } from '../../src/core/sbom/generate.js';
import { parsePythonTargetProfile } from '../../src/core/dependencies/python-target.js';
import {
  npmProvenanceIdentityDigest,
  parseNpmProvenancePolicy
} from '../../src/providers/npm/provenance.js';

const spdxSchema = JSON.parse(
  await readFile(
    new URL('../fixtures/spdx-2.3.1-schema.json', import.meta.url),
    'utf8'
  )
) as object;

function validatePurls(document: Record<string, unknown>): void {
  const values =
    document.bomFormat === 'CycloneDX'
      ? (document.components as Array<{ purl?: string }>).map(
          (component) => component.purl
        )
      : (
          document.packages as Array<{
            externalRefs?: Array<{
              referenceType?: string;
              referenceLocator?: string;
            }>;
          }>
        )
          .flatMap((pkg) => pkg.externalRefs ?? [])
          .filter((reference) => reference.referenceType === 'purl')
          .map((reference) => reference.referenceLocator);
  for (const value of values) {
    if (!value) continue;
    expect(() => PackageURL.fromString(value), value).not.toThrow();
  }
}

async function expectValidCycloneDx(
  document: Record<string, unknown>
): Promise<void> {
  const validator = new CycloneDxValidation.JsonValidator(
    CycloneDxSpec.Version.v1dot5
  );
  await expect(validator.validate(JSON.stringify(document))).resolves.toBe(
    null
  );
  validatePurls(document);
}

function expectValidSpdx(document: Record<string, unknown>): void {
  const ajv = new Ajv2019({ allErrors: true, strict: false });
  addFormats(ajv);
  const validate = ajv.compile(spdxSchema);
  expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
  validatePurls(document);
}

describe('SBOM generation', () => {
  it('uses canonical npm scoped package purls', () => {
    expect(npmPurl('@types/node', '22.0.0')).toBe(
      'pkg:npm/%40types/node@22.0.0'
    );
    expect(npmPurl('left-pad', '1.3.0')).toBe('pkg:npm/left-pad@1.3.0');
    expect(npmPurl('@scope/pkg:extra', '1.0.0+build/metadata')).toBe(
      'pkg:npm/%40scope/pkg%3Aextra@1.0.0%2Bbuild%2Fmetadata'
    );
    expect(() => npmPurl('@scope/', '1.0.0')).toThrow(
      'npm package URL name is invalid'
    );
    expect(() => npmPurl('name', '')).toThrow(
      'npm package URL version is invalid'
    );

    const parsed = PackageURL.fromString(npmPurl('@types/node', '22.0.0'));
    expect(parsed.type).toBe('npm');
    expect(parsed.namespace).toBe('@types');
    expect(parsed.name).toBe('node');
    expect(parsed.version).toBe('22.0.0');

    const escaped = PackageURL.fromString(
      npmPurl('@scope/pkg:extra', '1.0.0+build/metadata')
    );
    expect(escaped.namespace).toBe('@scope');
    expect(escaped.name).toBe('pkg:extra');
    expect(escaped.version).toBe('1.0.0+build/metadata');
  });

  async function fixture(): Promise<string> {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-sbom-'));

    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'fixture',
        version: '1.0.0',
        license: 'MIT',
        dependencies: {
          express: '^5.0.0'
        }
      })
    );

    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'fixture',
            version: '1.0.0',
            dependencies: {
              express: '^5.0.0'
            }
          },
          'node_modules/express': {
            version: '5.0.0',
            dependencies: {
              router: '^2.0.0'
            }
          },
          'node_modules/router': {
            version: '2.0.0'
          }
        }
      })
    );

    return root;
  }

  it('generates CycloneDX 1.5 JSON with resolved relationships', async () => {
    const root = await fixture();

    try {
      const document = await generateSbom(root, 'cyclonedx');

      expect(document.bomFormat).toBe('CycloneDX');
      expect(document.specVersion).toBe('1.5');
      expect((document.components as unknown[]).length).toBe(2);

      const relationships = document.dependencies as Array<{
        ref: string;
        dependsOn: string[];
      }>;
      const rootRelationship = relationships[0];
      const expressRelationship = relationships.find(
        (relationship) => relationship.ref === rootRelationship?.dependsOn[0]
      );

      expect(rootRelationship?.dependsOn).toHaveLength(1);
      expect(expressRelationship?.dependsOn).toHaveLength(1);

      await expectValidCycloneDx(document);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('separates declared artifact hashes from publisher trust and code safety', async () => {
    const root = await fixture();
    try {
      const initialSpdx = await generateSbom(root, 'spdx');
      const lockPath = path.join(root, 'package-lock.json');
      const lock = JSON.parse(await readFile(lockPath, 'utf8')) as {
        packages: Record<string, { integrity?: string }>;
      };
      const express = lock.packages['node_modules/express'];
      if (!express) throw new Error('fixture needs an express package');
      express.integrity = `sha512-${Buffer.alloc(64, 0x42).toString('base64')}`;
      await writeFile(lockPath, JSON.stringify(lock));

      const cyclonedx = await generateSbom(root, 'cyclonedx');
      await expectValidCycloneDx(cyclonedx);
      const components = cyclonedx.components as Array<{
        name: string;
        properties: Array<{ name: string; value: string }>;
      }>;
      const expressComponent = components.find(
        (item) => item.name === 'express'
      );
      expect(expressComponent?.properties).toEqual(
        expect.arrayContaining([
          {
            name: 'toolip:artifactIntegrityStatus',
            value: 'declared-not-verified'
          },
          { name: 'toolip:publisherTrustStatus', value: 'unknown' },
          { name: 'toolip:codeSafetyStatus', value: 'not-asserted' },
          {
            name: 'toolip:declaredIntegrity',
            value: express.integrity
          }
        ])
      );
      const routerComponent = components.find((item) => item.name === 'router');
      expect(routerComponent?.properties).toContainEqual({
        name: 'toolip:artifactIntegrityStatus',
        value: 'unknown'
      });

      const spdx = await generateSbom(root, 'spdx');
      expectValidSpdx(spdx);
      expect(spdx.documentNamespace).not.toBe(initialSpdx.documentNamespace);
      const packages = spdx.packages as Array<{
        name: string;
        sourceInfo: string;
      }>;
      expect(
        packages.find((item) => item.name === 'express')?.sourceInfo
      ).toContain(
        'artifact integrity: declared-not-verified; publisher trust: unknown; code safety: not asserted'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('emits verified publisher identity only when the opt-in trust result matches the exact lock identity', async () => {
    const root = await fixture();
    try {
      const lockPath = path.join(root, 'package-lock.json');
      const lock = JSON.parse(await readFile(lockPath, 'utf8')) as {
        packages: Record<string, { integrity?: string; resolved?: string }>;
      };
      const express = lock.packages['node_modules/express'];
      if (!express) throw new Error('fixture needs an express package');
      express.integrity = `sha512-${Buffer.alloc(64, 0x42).toString('base64')}`;
      express.resolved =
        'https://registry.npmjs.org/express/-/express-5.0.0.tgz';
      await writeFile(lockPath, JSON.stringify(lock));
      const trust = {
        certificateIssuer: 'https://token.actions.githubusercontent.com',
        certificateIdentity:
          'https://github.com/expressjs/express/.github/workflows/release.yml@refs/tags/v5.0.0',
        sourceRepository: 'https://github.com/expressjs/express'
      };
      const policy = parseNpmProvenancePolicy({
        version: 1,
        packages: { express: trust }
      });
      const verifier = vi.fn(async (identity) => ({
        identityDigest: npmProvenanceIdentityDigest(identity),
        name: identity.name,
        version: identity.version,
        status: 'verified' as const,
        reason: 'verified' as const,
        sourceRepository: trust.sourceRepository,
        certificateIssuer: trust.certificateIssuer,
        certificateIdentity: trust.certificateIdentity,
        artifactIntegrity: 'verified' as const
      }));

      const cyclonedx = await generateSbom(root, 'cyclonedx', {
        npmProvenancePolicy: policy,
        allowPublicScope: true,
        npmProvenanceVerifier: verifier
      });
      const component = (
        cyclonedx.components as Array<{
          name: string;
          properties: Array<{ name: string; value: string }>;
        }>
      ).find((item) => item.name === 'express');
      expect(component?.properties).toEqual(
        expect.arrayContaining([
          { name: 'toolip:publisherTrustStatus', value: 'verified' },
          { name: 'toolip:provenanceVerificationStatus', value: 'verified' },
          {
            name: 'toolip:verifiedSourceRepository',
            value: trust.sourceRepository
          },
          {
            name: 'toolip:artifactIntegrityStatus',
            value: 'verified'
          },
          { name: 'toolip:codeSafetyStatus', value: 'not-asserted' }
        ])
      );
      await expectValidCycloneDx(cyclonedx);

      const spdx = await generateSbom(root, 'spdx', {
        npmProvenancePolicy: policy,
        allowPublicScope: true,
        npmProvenanceVerifier: verifier
      });
      const expressPackage = (
        spdx.packages as Array<{ name: string; sourceInfo?: string }>
      ).find((item) => item.name === 'express');
      expect(expressPackage?.sourceInfo).toContain('publisher trust: verified');
      expect(expressPackage?.sourceInfo).toContain(
        'artifact integrity: verified'
      );
      expect(expressPackage?.sourceInfo).toContain('code safety: not asserted');
      expect(expressPackage?.sourceInfo).toContain(
        `verified source repository: ${trust.sourceRepository}`
      );
      expectValidSpdx(spdx);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('generates SPDX 2.3 JSON with graph relationships', async () => {
    const root = await fixture();

    try {
      const document = await generateSbom(root, 'spdx');

      expect(document.spdxVersion).toBe('SPDX-2.3');
      expect((document.packages as unknown[]).length).toBe(3);
      expect((document.relationships as unknown[]).length).toBe(2);

      expectValidSpdx(document);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('uses a reproducible SPDX namespace for the same resolved graph', async () => {
    const root = await fixture();
    try {
      const first = await generateSbom(root, 'spdx');
      const second = await generateSbom(root, 'spdx');
      expect(first.documentNamespace).toBe(second.documentNamespace);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps scoped aliases and duplicate installed instances distinct in both formats', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-sbom-instances-')
    );
    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          name: 'instance-fixture',
          version: '1.0.0',
          dependencies: {
            '@scope/tool': '^1.0.0',
            alias: 'npm:real-package@^1.0.0',
            parent: '^1.0.0'
          }
        })
      );
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          name: 'instance-fixture',
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'instance-fixture',
              version: '1.0.0',
              dependencies: {
                '@scope/tool': '^1.0.0',
                alias: 'npm:real-package@^1.0.0',
                parent: '^1.0.0'
              }
            },
            'node_modules/@scope/tool': { version: '1.2.0' },
            'node_modules/alias': {
              name: 'real-package',
              version: '1.1.0'
            },
            'node_modules/parent': {
              version: '1.0.0',
              dependencies: { '@scope/tool': '^2.0.0' }
            },
            'node_modules/parent/node_modules/@scope/tool': {
              version: '2.1.0'
            }
          }
        })
      );

      const cyclonedx = await generateSbom(root, 'cyclonedx');
      const components = cyclonedx.components as Array<{
        name: string;
        version: string;
        purl: string;
        'bom-ref': string;
      }>;
      const scoped = components.filter(
        (component) => component.name === '@scope/tool'
      );
      expect(scoped.map((component) => component.version).sort()).toEqual([
        '1.2.0',
        '2.1.0'
      ]);
      expect(scoped.map((component) => component.purl)).toEqual([
        'pkg:npm/%40scope/tool@1.2.0',
        'pkg:npm/%40scope/tool@2.1.0'
      ]);
      expect(
        new Set(scoped.map((component) => component['bom-ref'])).size
      ).toBe(2);
      expect(components).toContainEqual(
        expect.objectContaining({
          name: 'real-package',
          purl: 'pkg:npm/real-package@1.1.0'
        })
      );
      await expectValidCycloneDx(cyclonedx);

      const spdx = await generateSbom(root, 'spdx');
      const packages = spdx.packages as Array<{
        name: string;
        versionInfo?: string;
        SPDXID: string;
        externalRefs?: Array<{
          referenceType: string;
          referenceLocator: string;
        }>;
      }>;
      const spdxScoped = packages.filter((pkg) => pkg.name === '@scope/tool');
      expect(spdxScoped).toHaveLength(2);
      expect(new Set(spdxScoped.map((pkg) => pkg.SPDXID)).size).toBe(2);
      expect(spdxScoped.flatMap((pkg) => pkg.externalRefs ?? [])).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            referenceType: 'purl',
            referenceLocator: 'pkg:npm/%40scope/tool@1.2.0'
          }),
          expect.objectContaining({
            referenceType: 'purl',
            referenceLocator: 'pkg:npm/%40scope/tool@2.1.0'
          })
        ])
      );
      expectValidSpdx(spdx);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('includes exact Cargo packages in a non-npm CycloneDX inventory', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-sbom-cargo-'));
    try {
      await writeFile(
        path.join(root, 'Cargo.lock'),
        'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.188"\n'
      );
      const document = await generateSbom(root, 'cyclonedx');
      const components = document.components as Array<{
        name: string;
        purl: string;
      }>;
      expect(components).toEqual([
        expect.objectContaining({
          name: 'serde',
          purl: 'pkg:cargo/serde@1.0.188'
        })
      ]);
      await expectValidCycloneDx(document);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('retains Maven classifiers and artifact types in CycloneDX package URLs', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-sbom-maven-'));
    try {
      await writeFile(
        path.join(root, 'maven-dependency-tree.json'),
        JSON.stringify({
          groupId: 'org.acme',
          artifactId: 'service',
          version: '1.0.0',
          children: [
            {
              groupId: 'org.example',
              artifactId: 'native',
              version: '2.0.0',
              type: 'zip',
              classifier: 'linux-x64',
              scope: 'runtime',
              children: []
            }
          ]
        })
      );
      const document = await generateSbom(root, 'cyclonedx');
      const components = document.components as Array<{
        name: string;
        purl: string;
      }>;
      expect(components).toContainEqual(
        expect.objectContaining({
          name: 'org.example:native',
          purl: 'pkg:maven/org.example/native@2.0.0?classifier=linux-x64&type=zip'
        })
      );
      await expectValidCycloneDx(document);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('emits Maven parent and BOM resolved fixture versions in CycloneDX', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-sbom-maven-fixture-')
    );
    try {
      const captured = await readFile(
        new URL('../fixtures/java/maven-parent-bom-tree.json', import.meta.url),
        'utf8'
      );
      await writeFile(path.join(root, 'maven-dependency-tree.json'), captured);

      const document = await generateSbom(root, 'cyclonedx');
      const components = document.components as Array<{
        name: string;
        purl: string;
      }>;
      expect(components).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: 'org.apache.commons:commons-lang3',
            purl: 'pkg:maven/org.apache.commons/commons-lang3@3.16.0'
          }),
          expect.objectContaining({
            name: 'org.junit.jupiter:junit-jupiter-api',
            purl: 'pkg:maven/org.junit.jupiter/junit-jupiter-api@5.11.4'
          })
        ])
      );
      await expectValidCycloneDx(document);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('emits exact Gradle multi-module graph versions in CycloneDX', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-sbom-gradle-fixture-')
    );
    try {
      const captured = await readFile(
        new URL(
          '../fixtures/java/gradle/gradle-dependencies.json',
          import.meta.url
        ),
        'utf8'
      );
      await writeFile(path.join(root, 'gradle-dependencies.json'), captured);

      const document = await generateSbom(root, 'cyclonedx');
      const components = document.components as Array<{
        name: string;
        purl: string;
      }>;
      expect(components).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: 'org.apache.commons:commons-lang3',
            purl: 'pkg:maven/org.apache.commons/commons-lang3@3.15.0'
          }),
          expect.objectContaining({
            name: 'org.apache.commons:commons-lang3',
            purl: 'pkg:maven/org.apache.commons/commons-lang3@3.16.0'
          }),
          expect.objectContaining({
            name: 'org.apache.commons:commons-text',
            purl: 'pkg:maven/org.apache.commons/commons-text@1.12.0'
          })
        ])
      );
      await expectValidCycloneDx(document);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('emits the exact Maven text-tree classifier PURL', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-sbom-maven-text-')
    );
    try {
      await writeFile(
        path.join(root, 'maven-dependency-tree.txt'),
        [
          '[INFO] app:service:jar:1.0.0',
          '[INFO] +- org.example:native:zip:linux-x64:2.0.0:runtime',
          '[INFO]    \\- org.example:helper:jar:3.0.0:compile'
        ].join('\n')
      );

      const document = await generateSbom(root, 'cyclonedx');
      const components = document.components as Array<{
        name: string;
        purl: string;
      }>;
      expect(components).toContainEqual(
        expect.objectContaining({
          name: 'org.example:native',
          purl: 'pkg:maven/org.example/native@2.0.0?classifier=linux-x64&type=zip'
        })
      );
      await expectValidCycloneDx(document);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('normalizes Python distribution names using PEP 503 in CycloneDX purls', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-sbom-pypi-'));
    try {
      await writeFile(
        path.join(root, 'Pipfile.lock'),
        JSON.stringify({
          _meta: {
            requires: { python_version: '3.12' },
            sources: [
              { name: 'pypi', url: 'https://pypi.org/simple', verify_ssl: true }
            ]
          },
          default: {
            'My_Package.Name': { version: '==1.2.3' }
          },
          develop: {}
        })
      );
      const document = await generateSbom(root, 'cyclonedx');
      expect(document.components).toEqual([
        expect.objectContaining({
          name: 'my-package-name',
          purl: 'pkg:pypi/my-package-name@1.2.3'
        })
      ]);
      await expectValidCycloneDx(document);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('resolves dependency identities only from the caller supplied immutable source', async () => {
    const root = await fixture();
    try {
      const capturedLock = JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'fixture',
            version: '1.0.0',
            dependencies: { express: '^5.0.0' }
          },
          'node_modules/express': { version: '5.4.0' }
        }
      });
      const sourceFiles = new Map([
        [
          'package.json',
          JSON.stringify({ name: 'captured-project', version: '2.0.0' })
        ],
        ['package-lock.json', capturedLock]
      ]);
      const document = await generateSbom(root, 'cyclonedx', {
        fileSource: {
          files: [...sourceFiles.keys()],
          hasFile: (file) => sourceFiles.has(file),
          readText: (file) => sourceFiles.get(file)
        }
      });

      expect(document.metadata).toMatchObject({
        component: { name: 'captured-project', version: '2.0.0' }
      });
      expect(document.components).toEqual([
        expect.objectContaining({ name: 'express', version: '5.4.0' })
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it.each(['cyclonedx', 'spdx'] as const)(
    'cancels %s serialization after bounded graph work has started',
    async (format) => {
      const packageCount = 768;
      const dependencies = Object.fromEntries(
        Array.from({ length: packageCount }, (_, index) => [
          `package-${index}`,
          '1.0.0'
        ])
      );
      const packages = Object.fromEntries([
        ['', { name: 'cancel-fixture', version: '1.0.0', dependencies }],
        ...Object.keys(dependencies).map((name) => [
          `node_modules/${name}`,
          { version: '1.0.0' }
        ])
      ]);
      const sourceFiles = new Map([
        [
          'package.json',
          JSON.stringify({ name: 'cancel-fixture', version: '1.0.0' })
        ],
        [
          'package-lock.json',
          JSON.stringify({
            name: 'cancel-fixture',
            lockfileVersion: 3,
            packages
          })
        ]
      ]);
      const controller = new AbortController();
      let reads = 0;
      const generation = generateSbom('/immutable-fixture', format, {
        fileSource: {
          files: [...sourceFiles.keys()],
          hasFile: (file) => sourceFiles.has(file),
          readText: (file) => {
            reads++;
            return sourceFiles.get(file);
          }
        },
        signal: controller.signal
      });
      setTimeout(() => controller.abort(), 0);

      await expect(generation).rejects.toMatchObject({ name: 'AbortError' });
      expect(reads).toBeGreaterThan(0);
    }
  );

  it('includes the MVS-selected Go identity in the SBOM after explicit tool execution', async () => {
    const root = await fixture();
    const goModSum = `h1:${Buffer.alloc(32, 4).toString('base64')}`;
    const sourceFiles = new Map([
      ['package.json', await readFile(path.join(root, 'package.json'), 'utf8')],
      [
        'package-lock.json',
        await readFile(path.join(root, 'package-lock.json'), 'utf8')
      ],
      [
        'go.mod',
        'module example.test/app\ngo 1.24.0\nrequire example.test/lib v1.2.0\n'
      ],
      ['go.sum', `example.test/lib v1.3.0/go.mod ${goModSum}\n`]
    ]);
    const runner = async (input: {
      cwd: string;
      args: readonly string[];
    }): Promise<string> => {
      if (input.args[0] === 'version') return 'go version go1.24.1 linux/amd64';
      if (input.args[0] === 'list') {
        await writeFile(
          path.join(input.cwd, 'go.sum'),
          `example.test/lib v1.3.0/go.mod ${goModSum}\n`
        );
        return [
          JSON.stringify({ Path: 'example.test/app', Main: true }),
          JSON.stringify({
            Path: 'example.test/lib',
            Version: 'v1.3.0',
            GoModSum: goModSum
          })
        ].join('\n');
      }
      return 'example.test/app example.test/lib@v1.3.0\n';
    };
    try {
      const document = await generateSbom(root, 'cyclonedx', {
        fileSource: {
          files: [...sourceFiles.keys()],
          hasFile: (file) => sourceFiles.has(file),
          readText: (file) => sourceFiles.get(file)
        },
        allowGoToolExecution: true,
        goCommandRunner: runner
      });
      expect(document.components).toContainEqual(
        expect.objectContaining({
          name: 'example.test/lib',
          version: 'v1.3.0',
          purl: 'pkg:golang/example.test/lib@v1.3.0'
        })
      );
      expect(document.metadata).toMatchObject({
        properties: expect.arrayContaining([
          expect.objectContaining({
            name: 'toolip:dependencyGraphComplete',
            value: 'true'
          })
        ])
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('records the selected Python target and declared-only package hashes', async () => {
    const root = await fixture();
    try {
      await writeFile(
        path.join(root, 'requirements.txt'),
        [
          '--index-url https://pypi.org/simple',
          `sample-pkg==1.2.3 ; python_version < "3.12" --hash=sha256:${'a'.repeat(64)}`
        ].join('\n')
      );
      const target = parsePythonTargetProfile({
        id: 'py311-linux',
        environment: {
          implementation_name: 'cpython',
          implementation_version: '3.11.9',
          os_name: 'posix',
          platform_machine: 'x86_64',
          platform_python_implementation: 'CPython',
          platform_release: '6.8.0',
          platform_system: 'Linux',
          platform_version: 'test-release',
          python_full_version: '3.11.9',
          python_version: '3.11',
          sys_platform: 'linux'
        }
      });
      const document = await generateSbom(root, 'cyclonedx', {
        pythonTarget: target
      });
      await expectValidCycloneDx(document);
      expect(document.components).toContainEqual(
        expect.objectContaining({
          name: 'sample-pkg',
          version: '1.2.3',
          properties: expect.arrayContaining([
            {
              name: 'toolip:resolutionTarget',
              value: 'py311-linux'
            },
            {
              name: 'toolip:artifactIntegrityStatus',
              value: 'declared-not-verified'
            }
          ])
        })
      );

      const spdx = await generateSbom(root, 'spdx', {
        pythonTarget: target
      });
      expectValidSpdx(spdx);
      expect(spdx.packages).toContainEqual(
        expect.objectContaining({
          name: 'sample-pkg',
          sourceInfo: expect.stringContaining('resolution target: py311-linux')
        })
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('passes an explicit Cargo target through SBOM graph resolution', async () => {
    const root = await fixture();
    try {
      await writeFile(
        path.join(root, 'Cargo.toml'),
        [
          '[package]',
          'name = "fixture-rust"',
          'version = "0.1.0"',
          'edition = "2021"',
          '',
          '[workspace]',
          'members = ["crates/windows-helper"]',
          'resolver = "2"',
          '',
          '[features]',
          'default = ["safe"]',
          'safe = []',
          '',
          '[target."cfg(target_os = \\"windows\\")".dependencies]',
          'windows-helper = { path = "crates/windows-helper", features = ["win"] }'
        ].join('\n')
      );
      await mkdir(path.join(root, 'crates/windows-helper'), {
        recursive: true
      });
      await writeFile(
        path.join(root, 'crates/windows-helper/Cargo.toml'),
        [
          '[package]',
          'name = "windows-helper"',
          'version = "0.1.0"',
          'edition = "2021"',
          '',
          '[features]',
          'win = []'
        ].join('\n')
      );
      await writeFile(
        path.join(root, 'Cargo.lock'),
        [
          'version = 4',
          '',
          '[[package]]',
          'name = "fixture-rust"',
          'version = "0.1.0"',
          'dependencies = ["windows-helper"]',
          '',
          '[[package]]',
          'name = "windows-helper"',
          'version = "0.1.0"'
        ].join('\n')
      );

      const linux = await generateSbom(root, 'cyclonedx', {
        cargoTarget: 'x86_64-unknown-linux-gnu'
      });
      await expectValidCycloneDx(linux);
      const linuxComponents = linux.components as Array<{
        name: string;
        'bom-ref': string;
        properties: Array<{ name: string; value: string }>;
      }>;
      const rustApp = linuxComponents.find(
        (component) => component.name === 'fixture-rust'
      );
      expect(rustApp?.properties).toEqual(
        expect.arrayContaining([
          {
            name: 'toolip:resolutionTarget',
            value: 'x86_64-unknown-linux-gnu'
          },
          {
            name: 'toolip:activeCargoFeatures',
            value: '["default","safe"]'
          }
        ])
      );
      const linuxDependencies = linux.dependencies as Array<{
        ref: string;
        dependsOn: string[];
      }>;
      expect(
        linuxDependencies.find((item) => item.ref === rustApp?.['bom-ref'])
          ?.dependsOn
      ).not.toContain(
        linuxComponents.find(
          (component) => component.name === 'windows-helper'
        )?.['bom-ref']
      );

      const windows = await generateSbom(root, 'spdx', {
        cargoTarget: 'x86_64-pc-windows-msvc'
      });
      expectValidSpdx(windows);
      const spdxPackages = windows.packages as Array<{
        name: string;
        sourceInfo: string;
      }>;
      expect(
        spdxPackages.find((item) => item.name === 'fixture-rust')?.sourceInfo
      ).toContain('resolution target: x86_64-pc-windows-msvc');
      expect(
        spdxPackages.find((item) => item.name === 'fixture-rust')?.sourceInfo
      ).toContain('active Cargo features: default,safe');
      expect(spdxPackages.map((item) => item.name)).toContain('windows-helper');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('records unavailable vendored Go artifact integrity without upgrading it to verified', async () => {
    const root = await fixture();
    try {
      await writeFile(
        path.join(root, 'go.mod'),
        'module example.test/app\ngo 1.24.0\nrequire example.test/lib v1.2.3\n'
      );
      await mkdir(path.join(root, 'vendor'), { recursive: true });
      await writeFile(
        path.join(root, 'vendor', 'modules.txt'),
        [
          '# example.test/lib v1.2.3',
          '## explicit; go 1.24.0',
          'example.test/lib/pkg'
        ].join('\n')
      );
      const document = await generateSbom(root, 'cyclonedx');
      await expectValidCycloneDx(document);
      expect(document.components).toContainEqual(
        expect.objectContaining({
          name: 'example.test/lib',
          version: 'v1.2.3',
          properties: expect.arrayContaining([
            {
              name: 'toolip:artifactIntegrityStatus',
              value: 'unavailable'
            }
          ])
        })
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
