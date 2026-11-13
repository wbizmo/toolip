import { copyFile, cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  readNpmDependencyGraph,
  readNpmDependencyInventory
} from '../../src/core/dependencies/inventory.js';
import { ReachabilityAnalyzer } from '../../src/analyzers/reachability/reachability-analyzer.js';
import { generateSbom } from '../../src/core/sbom/generate.js';

const roots: string[] = [];
const strongIntegrity = `sha512-${Buffer.alloc(64, 0x5a).toString('base64')}`;

async function fixture(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-lock-resolver-'));
  roots.push(root);
  return root;
}

async function generatedManagerFixture(manager: string): Promise<string> {
  const root = await fixture();
  const fixtureRoot = path.resolve('tests/fixtures/package-managers');
  const projectRoot = manager.startsWith('yarn-berry-')
    ? path.join(fixtureRoot, manager, 'project')
    : path.join(fixtureRoot, 'project');
  await cp(projectRoot, root, { recursive: true });
  const lockfile = manager.startsWith('npm-')
    ? 'package-lock.json'
    : manager.startsWith('pnpm-')
      ? 'pnpm-lock.yaml'
      : 'yarn.lock';
  await copyFile(
    path.join(fixtureRoot, manager, lockfile),
    path.join(root, lockfile)
  );
  return root;
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

describe('pnpm and Yarn exact dependency graphs', () => {
  it.each([
    ['npm-v2', '18.2.0'],
    ['npm-v3', '18.2.0'],
    ['pnpm-v8', '18.2.0'],
    ['pnpm-v9', '18.2.0'],
    ['yarn-classic-v1', '18.2.0'],
    ['yarn-berry-v2', undefined],
    ['yarn-berry-v3', undefined],
    ['yarn-berry-v4', undefined]
  ] as const)(
    'matches manager-generated %s workspace and exact lock identities',
    async (manager, reactVersion) => {
      const root = await generatedManagerFixture(manager);
      const graph = await readNpmDependencyGraph(root);

      expect(graph).toMatchObject({
        complete: true,
        unresolvedDependencies: []
      });
      expect(
        graph.packages.filter((item) =>
          item.name.startsWith('@toolip-fixture/')
        )
      ).toHaveLength(3);
      expect(
        graph.packages.some((item) => item.version === '0.0.0-use.local')
      ).toBe(false);
      expect(graph.packages).toHaveLength(
        manager.startsWith('yarn-berry-')
          ? 3
          : manager.startsWith('pnpm-')
            ? 11
            : 13
      );
      expect(graph.edges).toHaveLength(
        manager === 'npm-v2' || manager === 'npm-v3'
          ? 19
          : manager === 'pnpm-v9'
            ? 18
            : manager === 'pnpm-v8'
              ? 17
              : manager === 'yarn-classic-v1'
                ? 16
                : 3
      );
      expect(
        graph.edges.every(
          (edge) =>
            graph.packages.some((item) => item.id === edge.to) &&
            (edge.from === 'root' ||
              graph.packages.some((item) => item.id === edge.from))
        )
      ).toBe(true);
      for (const [workspacePath, appName] of [
        ['packages/app-18', '@toolip-fixture/app-18'],
        ['packages/app-19', '@toolip-fixture/app-19'],
        ['packages/optional-peer', '@toolip-fixture/optional-peer']
      ]) {
        const workspace = graph.packages.find(
          (item) => item.workspace === workspacePath
        );
        expect(workspace?.name).toBe(appName);
        expect(graph.edges).toContainEqual(
          expect.objectContaining({
            from: 'root',
            to: workspace?.id,
            name: appName
          })
        );
      }
      if (reactVersion) {
        expect(
          graph.packages
            .filter((item) => item.name === 'react')
            .map((item) => item.version)
            .filter((version) => version === reactVersion)
        ).not.toHaveLength(0);
        for (const [alias, version] of [
          ['react18-alias', '18.2.0'],
          ['react19-alias', '19.0.0']
        ]) {
          const target = graph.edges.find((edge) => edge.alias === alias);
          expect(target).toMatchObject({ name: 'react', alias });
          expect(
            graph.packages.find((item) => item.id === target?.to)?.version
          ).toBe(version);
        }
        for (const [workspacePath, version] of [
          ['packages/app-18', '18.2.0'],
          ['packages/app-19', '19.0.0']
        ]) {
          const owner = graph.packages.find(
            (item) => item.workspace === workspacePath
          );
          for (const name of ['react', 'react-dom']) {
            const edge = graph.edges.find(
              (item) => item.from === owner?.id && item.name === name
            );
            expect(edge).toBeDefined();
            expect(
              graph.packages.find((item) => item.id === edge?.to)
            ).toMatchObject({ name, version });
          }
        }
        if (manager.startsWith('npm-')) {
          expect(
            graph.packages.find(
              (item) => item.installPath === 'node_modules/react18-alias'
            )
          ).toMatchObject({ name: 'react', installName: 'react18-alias' });
          expect(
            graph.packages.find(
              (item) => item.installPath === 'node_modules/react19-alias'
            )
          ).toMatchObject({ name: 'react', installName: 'react19-alias' });
          expect(
            graph.packages.find(
              (item) => item.installPath === 'node_modules/react'
            )
          ).toMatchObject({ name: 'react', installName: 'react' });
          expect(
            graph.packages.find(
              (item) =>
                item.installPath === 'packages/app-19/node_modules/react-dom'
            )
          ).toMatchObject({ name: 'react-dom', installName: 'react-dom' });
        }
        expect(
          graph.packages
            .filter((item) => item.name === 'react' && item.integrity)
            .every(
              (item) => item.artifactIntegrityStatus === 'declared-not-verified'
            )
        ).toBe(true);
      }

      const cyclonedx = await generateSbom(root, 'cyclonedx');
      const cyclonedxPurls = (
        cyclonedx.components as Array<{ purl?: string }>
      ).map((item) => item.purl);
      const spdx = await generateSbom(root, 'spdx');
      const spdxPurls = (
        spdx.packages as Array<{
          externalRefs?: Array<{
            referenceType?: string;
            referenceLocator?: string;
          }>;
        }>
      )
        .flatMap((item) => item.externalRefs ?? [])
        .filter((item) => item.referenceType === 'purl')
        .map((item) => item.referenceLocator);
      const expectedPurl = reactVersion
        ? 'pkg:npm/react@18.2.0'
        : 'pkg:npm/%40toolip-fixture/app-18@1.0.0';
      expect(cyclonedxPurls).toContain(expectedPurl);
      expect(spdxPurls).toContain(expectedPurl);
      if (reactVersion) {
        for (const version of ['18.2.0', '19.0.0']) {
          const expectedInstances = graph.packages.filter(
            (item) => item.name === 'react' && item.version === version
          ).length;
          const purl = `pkg:npm/react@${version}`;
          expect(cyclonedxPurls.filter((item) => item === purl)).toHaveLength(
            expectedInstances
          );
          expect(spdxPurls.filter((item) => item === purl)).toHaveLength(
            expectedInstances
          );
        }
      }
    }
  );

  it.each(['npm-v3', 'yarn-classic-v1'] as const)(
    'uses the actual installed alias path for %s reachability',
    async (manager) => {
      const root = await generatedManagerFixture(manager);
      await mkdir(path.join(root, 'node_modules', 'react18-alias'), {
        recursive: true
      });
      await writeFile(
        path.join(root, 'node_modules', 'react18-alias', 'package.json'),
        JSON.stringify({
          name: 'react',
          version: '18.2.0',
          main: 'index.js'
        })
      );
      await writeFile(
        path.join(root, 'node_modules', 'react18-alias', 'index.js'),
        'module.exports = {};'
      );
      await writeFile(
        path.join(root, 'entry.ts'),
        "import React from 'react18-alias'; export default React;"
      );

      const result = await new ReachabilityAnalyzer().analyze({ root });
      const packages = result.metadata?.packages as Array<{
        packageName: string;
        packageVersion: string;
        installPath: string;
        state: string;
      }>;
      expect(
        packages.find(
          (item) =>
            item.packageName === 'react' &&
            item.packageVersion === '18.2.0' &&
            item.installPath === 'node_modules/react18-alias'
        )?.state
      ).toBe('reachable');
    }
  );

  it('keeps npm alias identity, custom registry origin and integrity unverified', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {
            dependencies: { alias: 'npm:@scope/real@^1.0.0' }
          },
          'node_modules/alias': {
            name: '@scope/real',
            version: '1.4.2',
            resolved:
              'https://packages.example.test/npm/@scope/real/-/real-1.4.2.tgz',
            integrity: strongIntegrity
          }
        }
      })
    );

    const graph = await readNpmDependencyGraph(root);
    const target = graph.packages.find((item) => item.name === '@scope/real');
    expect(graph).toMatchObject({ manager: 'npm', complete: true });
    expect(target).toMatchObject({
      id: expect.stringContaining('node_modules/alias'),
      version: '1.4.2',
      registry: 'https://packages.example.test',
      integrity: strongIntegrity,
      artifactIntegrityStatus: 'declared-not-verified',
      resolutionConfidence: 'lockfile'
    });
    expect(target?.artifactIntegrityStatus).not.toBe('verified');
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: target?.id,
        name: '@scope/real',
        alias: 'alias',
        requirement: 'npm:@scope/real@^1.0.0'
      })
    );
  });

  it('derives npm root and nested scoped install names from lock paths', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/@scope/pkg': {
            version: '2.1.0',
            resolved: 'https://registry.npmjs.org/@scope/pkg/-/pkg-2.1.0.tgz'
          },
          'node_modules/parent': { version: '1.0.0' },
          'node_modules/parent/node_modules/@scope/pkg': {
            version: '3.4.0',
            resolved: 'https://registry.npmjs.org/@scope/pkg/-/pkg-3.4.0.tgz'
          }
        }
      })
    );

    const graph = await readNpmDependencyGraph(root);
    expect(
      graph.packages
        .filter((item) => item.name === '@scope/pkg')
        .map((item) => [item.installPath, item.installName, item.version])
        .sort(([left], [right]) => String(left).localeCompare(String(right)))
    ).toEqual([
      ['node_modules/@scope/pkg', '@scope/pkg', '2.1.0'],
      ['node_modules/parent/node_modules/@scope/pkg', '@scope/pkg', '3.4.0']
    ]);
  });

  it('marks malformed npm integrity and credential-bearing source URLs incomplete', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/private-pkg': {
            version: '1.0.0',
            resolved:
              'https://user:secret@packages.example.test/private-pkg.tgz',
            integrity: 'sha512-not-a-digest'
          }
        }
      })
    );

    const graph = await readNpmDependencyGraph(root);
    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain('npm-lockfile-source-url-unsafe');
    expect(graph.warnings).toContain('npm-lockfile-integrity-malformed');
    expect(graph.packages[0]).toMatchObject({
      artifactIntegrityStatus: 'unavailable'
    });
    expect(graph.packages[0]).not.toHaveProperty('registry');
    // Retain only the redacted locator for compatibility with source identity;
    // the warning and absent registry prohibit treating it as trusted.
    expect(graph.packages[0]?.resolved).toBe(
      'https://packages.example.test/private-pkg.tgz'
    );
    expect(JSON.stringify(graph)).not.toContain('secret');
  });

  it('resolves pnpm importer specifiers and peer-qualified package instances exactly', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pnpm-lock.yaml'),
      `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@scope/direct':
        specifier: ^2.0.0
        version: 2.1.0
packages:
  '@scope/direct@2.1.0':
    resolution:
      integrity: ${strongIntegrity}
  'leaf@1.0.0(react@18.2.0)':
    resolution: {}
snapshots:
  '@scope/direct@2.1.0':
    dependencies:
      leaf: 1.0.0(react@18.2.0)
  'leaf@1.0.0(react@18.2.0)': {}
`
    );

    const graph = await readNpmDependencyGraph(root);
    const direct = graph.packages.find((item) => item.name === '@scope/direct');
    const leaf = graph.packages.find((item) => item.name === 'leaf');
    expect(graph).toMatchObject({
      manager: 'pnpm',
      complete: true,
      warnings: []
    });
    expect(direct).toMatchObject({
      version: '2.1.0',
      direct: true,
      manager: 'pnpm',
      integrity: strongIntegrity
    });
    expect(leaf?.id).toBe('pnpm:leaf@1.0.0(react@18.2.0)');
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: direct?.id,
        to: leaf?.id,
        name: 'leaf',
        requirement: '1.0.0(react@18.2.0)'
      })
    );
  });

  it('resolves scoped npm aliases to the target package lock identity', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pnpm-lock.yaml'),
      `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias:
        specifier: npm:@scope/real@^2.0.0
        version: '@scope/real@2.4.1'
packages:
  '@scope/real@2.4.1':
    resolution:
      integrity: ${strongIntegrity}
snapshots:
  '@scope/real@2.4.1': {}
`
    );

    const graph = await readNpmDependencyGraph(root);
    const target = graph.packages.find((item) => item.name === '@scope/real');
    expect(graph).toMatchObject({ manager: 'pnpm', complete: true });
    expect(target).toMatchObject({ version: '2.4.1', direct: true });
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: target?.id,
        name: '@scope/real',
        alias: 'alias',
        requirement: 'npm:@scope/real@^2.0.0'
      })
    );
  });

  it('preserves pnpm v9 peer-qualified snapshot instances and their edges', async () => {
    // Reduced lockfile structure generated by pnpm 12.18.0 for two workspaces
    // using react-dom with different React peer contexts.
    const root = await fixture();
    await mkdir(path.join(root, 'packages', 'app-a'), { recursive: true });
    await mkdir(path.join(root, 'packages', 'app-b'), { recursive: true });
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ name: 'root', version: '1.0.0' })
    );
    await writeFile(
      path.join(root, 'packages', 'app-a', 'package.json'),
      JSON.stringify({ name: 'app-a', version: '1.0.0' })
    );
    await writeFile(
      path.join(root, 'packages', 'app-b', 'package.json'),
      JSON.stringify({ name: 'app-b', version: '1.0.0' })
    );
    await writeFile(
      path.join(root, 'pnpm-lock.yaml'),
      `lockfileVersion: '9.0'
importers:
  .: {}
  packages/app-a:
    dependencies:
      react:
        specifier: 18.2.0
        version: 18.2.0
      react-dom:
        specifier: 18.2.0
        version: 18.2.0(react@18.2.0)
  packages/app-b:
    dependencies:
      react:
        specifier: 19.0.0
        version: 19.0.0
      react-dom:
        specifier: 19.0.0
        version: 19.0.0(react@19.0.0)
packages:
  react-dom@18.2.0:
    resolution:
      integrity: ${strongIntegrity}
    peerDependencies:
      react: ^18.2.0
  react-dom@19.0.0:
    resolution:
      integrity: ${strongIntegrity}
    peerDependencies:
      react: ^19.0.0
  react@18.2.0:
    resolution:
      integrity: ${strongIntegrity}
  react@19.0.0:
    resolution:
      integrity: ${strongIntegrity}
  scheduler@0.23.2:
    resolution:
      integrity: ${strongIntegrity}
  scheduler@0.25.0:
    resolution:
      integrity: ${strongIntegrity}
snapshots:
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
      scheduler: 0.23.2
  react-dom@19.0.0(react@19.0.0):
    dependencies:
      react: 19.0.0
      scheduler: 0.25.0
  react@18.2.0: {}
  react@19.0.0: {}
  scheduler@0.23.2: {}
  scheduler@0.25.0: {}
`
    );

    const graph = await readNpmDependencyGraph(root);
    const apps = new Map(
      graph.packages
        .filter((item) => item.name === 'app-a' || item.name === 'app-b')
        .map((item) => [item.name, item.id])
    );
    const reactDoms = graph.packages.filter(
      (item) => item.name === 'react-dom'
    );
    expect(graph).toMatchObject({
      manager: 'pnpm',
      complete: true,
      warnings: []
    });
    expect(reactDoms).toHaveLength(2);
    expect(new Set(reactDoms.map((item) => item.id)).size).toBe(2);
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: apps.get('app-a'),
        to: reactDoms.find((item) => item.version === '18.2.0')?.id
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: apps.get('app-b'),
        to: reactDoms.find((item) => item.version === '19.0.0')?.id
      })
    );
    expect(
      graph.edges.filter((edge) =>
        reactDoms.some((item) => item.id === edge.from)
      )
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'scheduler', requirement: '0.23.2' }),
        expect.objectContaining({ name: 'scheduler', requirement: '0.25.0' })
      ])
    );
  });

  it('marks malformed pnpm package and snapshot records incomplete', async () => {
    for (const lockBody of [
      `packages:
  broken@1.0.0: null
snapshots:
  broken@1.0.0: {}`,
      `packages:
  broken@1.0.0: {}
snapshots:
  broken@1.0.0: null`
    ]) {
      const root = await fixture();
      await writeFile(
        path.join(root, 'pnpm-lock.yaml'),
        `lockfileVersion: '9.0'
importers:
  .: {}
${lockBody}
`
      );

      const graph = await readNpmDependencyGraph(root);
      expect(graph.complete).toBe(false);
      expect(graph.warnings.join('\n')).toMatch(
        /pnpm (?:package metadata|snapshot record) is malformed/u
      );
    }
  });

  it('treats the pnpm v9 snapshots map as authoritative even when empty', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pnpm-lock.yaml'),
      `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      unused:
        specifier: ^1.0.0
        version: 1.0.0
packages:
  unused@1.0.0:
    resolution: {}
snapshots: {}
`
    );

    const graph = await readNpmDependencyGraph(root);
    expect(graph.complete).toBe(false);
    expect(graph.packages).toEqual([]);
    expect(graph.unresolvedDependencies).toContainEqual(
      expect.objectContaining({ name: 'unused', requirement: '^1.0.0' })
    );
  });

  it('models pnpm workspace importers and their external dependencies', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ name: 'root', version: '1.0.0' })
    );
    await writeFile(
      path.join(root, 'pnpm-lock.yaml'),
      `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@ws/app':
        specifier: workspace:*
        version: link:packages/app
  packages/app:
    dependencies:
      '@ws/lib':
        specifier: workspace:*
        version: link:../lib
      external:
        specifier: ^2.0.0
        version: 2.1.0
  packages/lib: {}
packages:
  external@2.1.0:
    resolution: {}
snapshots:
  external@2.1.0: {}
`
    );
    await mkdir(path.join(root, 'packages', 'app'), { recursive: true });
    await mkdir(path.join(root, 'packages', 'lib'), { recursive: true });
    await writeFile(
      path.join(root, 'packages', 'app', 'package.json'),
      JSON.stringify({ name: '@ws/app', version: '1.0.0' })
    );
    await writeFile(
      path.join(root, 'packages', 'lib', 'package.json'),
      JSON.stringify({ name: '@ws/lib', version: '1.2.0' })
    );

    const graph = await readNpmDependencyGraph(root);
    const app = graph.packages.find((item) => item.name === '@ws/app');
    const lib = graph.packages.find((item) => item.name === '@ws/lib');
    const external = graph.packages.find((item) => item.name === 'external');
    expect(graph.complete).toBe(true);
    expect(app?.workspace).toBe('packages/app');
    expect(lib?.workspace).toBe('packages/lib');
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: app?.id,
        requirement: 'workspace:*'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({ from: app?.id, to: lib?.id })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: app?.id,
        to: external?.id,
        requirement: '^2.0.0'
      })
    );
  });

  it('resolves Yarn classic aliases and exact transitive descriptors', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'root',
        version: '1.0.0',
        dependencies: { foo: '^1.0.0' }
      })
    );
    await writeFile(
      path.join(root, 'yarn.lock'),
      `# yarn lockfile v1

foo@^1.0.0:
  version "1.2.0"
  resolved "https://registry.npmjs.org/foo/-/foo-1.2.0.tgz"
  integrity ${strongIntegrity}
  dependencies:
    child "^2.0.0"

child@^2.0.0:
  version "2.3.0"
`
    );

    const graph = await readNpmDependencyGraph(root);
    const foo = graph.packages.find((item) => item.name === 'foo');
    const child = graph.packages.find((item) => item.name === 'child');
    expect(graph).toMatchObject({ manager: 'yarn', complete: true });
    expect(foo).toMatchObject({
      version: '1.2.0',
      direct: true,
      resolved: 'https://registry.npmjs.org/foo/-/foo-1.2.0.tgz',
      integrity: strongIntegrity
    });
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: foo?.id,
        to: child?.id,
        requirement: '^2.0.0'
      })
    );
  });

  it.each([
    ['plain HTTP', 'http://registry.npmjs.org/foo/-/foo-1.2.0.tgz'],
    ['credential query', 'https://registry.npmjs.org/foo.tgz?token=secret'],
    [
      'credentialed HTTPS',
      'https://user:secret@registry.npmjs.org/foo/-/foo-1.2.0.tgz'
    ],
    ['nonstandard HTTPS port', 'https://registry.npmjs.org:8443/foo.tgz']
  ])(
    'marks Yarn %s source provenance incomplete without exposing it',
    async (_label, resolved) => {
      const root = await fixture();
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({ dependencies: { foo: '^1.0.0' } })
      );
      await writeFile(
        path.join(root, 'yarn.lock'),
        `# yarn lockfile v1

foo@^1.0.0:
  version "1.2.0"
  resolved "${resolved}"
  integrity ${strongIntegrity}
`
      );

      const graph = await readNpmDependencyGraph(root);

      expect(graph.complete).toBe(false);
      expect(graph.warnings).toContain('Yarn source URL is unsafe: foo@^1.0.0');
      expect(graph.warnings.join(' ')).not.toContain('secret');
      expect(graph.packages[0]?.resolved).toBeUndefined();
      expect(JSON.stringify(graph)).not.toContain('registry.npmjs.org');
    }
  );

  it('resolves Yarn Berry protocol descriptors without executing PnP files', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'root',
        version: '1.0.0',
        dependencies: { foo: '^1.0.0' }
      })
    );
    await writeFile(
      path.join(root, 'yarn.lock'),
      `__metadata:
  version: 8
  cacheKey: 10c0

"foo@npm:^1.0.0":
  version: 1.2.0
  resolution: "foo@npm:1.2.0"
  dependencies:
    child: "npm:^2.0.0"

"child@npm:^2.0.0":
  version: 2.3.0
  resolution: "child@npm:2.3.0"
`
    );

    const graph = await readNpmDependencyGraph(root);
    const foo = graph.packages.find((item) => item.name === 'foo');
    const child = graph.packages.find((item) => item.name === 'child');
    expect(graph).toMatchObject({ manager: 'yarn', complete: true });
    expect(foo?.installPath).toMatch(/^yarn:pnp\//u);
    expect(graph.edges).toContainEqual(
      expect.objectContaining({ from: foo?.id, to: child?.id })
    );
  });

  it('accepts supported Yarn Berry lock metadata versions and rejects unknown versions', async () => {
    for (const version of [4, 5, 6, 8]) {
      const root = await fixture();
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({ name: 'empty', version: '1.0.0' })
      );
      await writeFile(
        path.join(root, 'yarn.lock'),
        `__metadata:\n  version: ${version}\n`
      );
      await expect(readNpmDependencyGraph(root)).resolves.toMatchObject({
        manager: 'yarn',
        complete: true
      });
    }

    const unsupported = await fixture();
    await writeFile(
      path.join(unsupported, 'package.json'),
      JSON.stringify({ name: 'empty', version: '1.0.0' })
    );
    await writeFile(
      path.join(unsupported, 'yarn.lock'),
      '__metadata:\n  version: 99\n'
    );
    await expect(readNpmDependencyGraph(unsupported)).rejects.toThrow(
      /Yarn Berry lockfile metadata/u
    );
  });

  it('accepts Yarn Classic tarball checksum fragments without treating them as trust', async () => {
    const root = await fixture();
    const sha1 = 'a'.repeat(40);
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ dependencies: { foo: '^1.0.0' } })
    );
    await writeFile(
      path.join(root, 'yarn.lock'),
      `# yarn lockfile v1

foo@^1.0.0:
  version "1.2.0"
  resolved "https://registry.yarnpkg.com/foo/-/foo-1.2.0.tgz#${sha1}"
  integrity ${strongIntegrity}
`
    );

    const graph = await readNpmDependencyGraph(root);
    expect(graph).toMatchObject({ manager: 'yarn', complete: true });
    expect(graph.packages[0]).toMatchObject({
      version: '1.2.0',
      resolved: 'https://registry.yarnpkg.com/foo/-/foo-1.2.0.tgz',
      registry: 'https://registry.yarnpkg.com',
      artifactIntegrityStatus: 'declared-not-verified'
    });
  });

  it('does not treat an intentionally absent optional Yarn peer as an unresolved required edge', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'root',
        version: '1.0.0',
        dependencies: { foo: '^1.0.0' },
        peerDependencies: { optionalPeer: '^2.0.0' },
        peerDependenciesMeta: { optionalPeer: { optional: true } }
      })
    );
    await writeFile(
      path.join(root, 'yarn.lock'),
      '__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"foo@npm:^1.0.0":\n  version: 1.2.0\n  resolution: "foo@npm:1.2.0"\n'
    );
    const graph = await readNpmDependencyGraph(root);
    expect(graph).toMatchObject({ manager: 'yarn', complete: true });
    expect(graph.unresolvedDependencies).toEqual([]);
    expect(graph.rootDependencies).toHaveLength(1);
  });

  it('still flags an absent required Yarn peer as unresolved', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'root',
        version: '1.0.0',
        dependencies: { foo: '^1.0.0' },
        peerDependencies: { requiredPeer: '^2.0.0' }
      })
    );
    await writeFile(
      path.join(root, 'yarn.lock'),
      '__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"foo@npm:^1.0.0":\n  version: 1.2.0\n  resolution: "foo@npm:1.2.0"\n'
    );
    const graph = await readNpmDependencyGraph(root);
    expect(graph.complete).toBe(false);
    expect(graph.unresolvedDependencies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'requiredPeer',
          section: 'peerDependency'
        })
      ])
    );
  });

  it('honors Yarn Berry optional peer metadata without dropping required peer failures', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'root',
        version: '1.0.0',
        dependencies: { foo: '^1.0.0' }
      })
    );
    await writeFile(
      path.join(root, 'yarn.lock'),
      `__metadata:
  version: 8
  cacheKey: 10c0
"foo@npm:^1.0.0":
  version: 1.2.0
  resolution: "foo@npm:1.2.0"
  peerDependencies:
    optionalPeer: "npm:^2.0.0"
    requiredPeer: "npm:^3.0.0"
  peerDependenciesMeta:
    optionalPeer:
      optional: true
`
    );
    const graph = await readNpmDependencyGraph(root);
    expect(graph.complete).toBe(false);
    expect(graph.unresolvedDependencies).toContainEqual(
      expect.objectContaining({
        name: 'requiredPeer',
        section: 'peerDependency'
      })
    );
    expect(
      graph.unresolvedDependencies.some((item) => item.name === 'optionalPeer')
    ).toBe(false);
  });

  it('marks pnpm unsafe tarball URLs incomplete without retaining credentials', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pnpm-lock.yaml'),
      `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      foo:
        specifier: ^1.0.0
        version: 1.2.0
packages:
  foo@1.2.0:
    resolution:
      tarball: 'http://user:secret@registry.example/foo.tgz'
      integrity: ${strongIntegrity}
snapshots:
  foo@1.2.0: {}
`
    );

    const graph = await readNpmDependencyGraph(root);

    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain('pnpm source URL is unsafe: foo@1.2.0');
    expect(JSON.stringify(graph)).not.toContain('secret');
    expect(graph.packages[0]?.resolved).toBeUndefined();
  });

  it('resolves grouped Yarn Berry selectors to their shared exact instance', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'root',
        version: '1.0.0',
        dependencies: { foo: '^1.0.0' }
      })
    );
    await writeFile(
      path.join(root, 'yarn.lock'),
      `__metadata:
  version: 8

"foo@npm:^1.0.0, foo@npm:~1.0.0":
  version: 1.2.0
  resolution: "foo@npm:1.2.0"
  checksum: 10c0/abc
  dependencies:
    child: "npm:^2.0.0"

"child@npm:^2.0.0":
  version: 2.3.0
  resolution: "child@npm:2.3.0"
`
    );

    const graph = await readNpmDependencyGraph(root);
    const foo = graph.packages.find((item) => item.name === 'foo');
    const child = graph.packages.find((item) => item.name === 'child');
    expect(graph).toMatchObject({ manager: 'yarn', complete: true });
    expect(foo).toMatchObject({ version: '1.2.0', direct: true });
    expect(graph.unresolvedDependencies).toEqual([]);
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: foo?.id,
        name: 'foo',
        requirement: '^1.0.0'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: foo?.id,
        to: child?.id,
        name: 'child',
        requirement: 'npm:^2.0.0'
      })
    );
  });

  it('preserves distinct Yarn Berry peer-context instances sharing one archive', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'root',
        version: '1.0.0',
        dependencies: { 'app-a': '1.0.0', 'app-b': '1.0.0' }
      })
    );
    await writeFile(
      path.join(root, 'yarn.lock'),
      `__metadata:
  version: 8

"app-a@npm:1.0.0":
  version: 1.0.0
  resolution: "app-a@npm:1.0.0"
  dependencies:
    foo: "virtual:peer-a#npm:1.0.0"

"app-b@npm:1.0.0":
  version: 1.0.0
  resolution: "app-b@npm:1.0.0"
  dependencies:
    foo: "virtual:peer-b#npm:1.0.0"

"foo@virtual:peer-a#npm:1.0.0":
  version: 1.0.0
  resolution: "foo@npm:1.0.0"
  checksum: 10c0/shared

"foo@virtual:peer-b#npm:1.0.0":
  version: 1.0.0
  resolution: "foo@npm:1.0.0"
  checksum: 10c0/shared
`
    );

    const graph = await readNpmDependencyGraph(root);
    const apps = new Map(
      graph.packages
        .filter((item) => item.name === 'app-a' || item.name === 'app-b')
        .map((item) => [item.name, item.id])
    );
    const foos = graph.packages.filter((item) => item.name === 'foo');
    const appTargets = ['app-a', 'app-b'].map(
      (name) => graph.edges.find((edge) => edge.from === apps.get(name))?.to
    );

    expect(graph.complete).toBe(true);
    expect(foos).toHaveLength(2);
    expect(new Set(foos.map((item) => item.id)).size).toBe(2);
    expect(appTargets).toEqual(
      expect.arrayContaining(foos.map((item) => item.id))
    );
    expect(new Set(appTargets).size).toBe(2);
  });

  it('resolves Yarn workspace protocol edges to exact workspace identities', async () => {
    const root = await fixture();
    await mkdir(path.join(root, 'packages', 'library'), { recursive: true });
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'root',
        version: '1.0.0',
        workspaces: ['packages/*'],
        dependencies: { '@ws/library': 'workspace:^' }
      })
    );
    await writeFile(
      path.join(root, 'packages', 'library', 'package.json'),
      JSON.stringify({
        name: '@ws/library',
        version: '1.4.0',
        dependencies: { external: '^3.0.0' }
      })
    );
    await writeFile(
      path.join(root, 'yarn.lock'),
      `# yarn lockfile v1

external@^3.0.0:
  version "3.1.0"
`
    );

    const graph = await readNpmDependencyGraph(root);
    const workspace = graph.packages.find(
      (item) => item.name === '@ws/library'
    );
    const external = graph.packages.find((item) => item.name === 'external');
    expect(graph.complete).toBe(true);
    expect(workspace).toMatchObject({
      version: '1.4.0',
      workspace: 'packages/library'
    });
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: workspace?.id,
        requirement: 'workspace:^'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({ from: workspace?.id, to: external?.id })
    );
  });

  it('rejects symlinked lockfiles rather than following them', async () => {
    if (process.platform === 'win32') return;
    const root = await fixture();
    const outside = await fixture();
    await writeFile(
      path.join(outside, 'package-lock.json'),
      JSON.stringify({ lockfileVersion: 3, packages: {} })
    );
    const { symlink } = await import('node:fs/promises');
    await symlink(
      path.join(outside, 'package-lock.json'),
      path.join(root, 'package-lock.json')
    );
    await expect(readNpmDependencyGraph(root)).rejects.toMatchObject({
      code: 'DEPENDENCY_LOCKFILE_INVALID'
    });
  });

  it('does not fabricate graph edges when a lockfile descriptor is unresolved', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pnpm-lock.yaml'),
      `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      absent:
        specifier: ^1.0.0
        version: 1.2.0
packages: {}
snapshots: {}
`
    );

    const graph = await readNpmDependencyGraph(root);
    expect(graph.complete).toBe(false);
    expect(graph.edges).toEqual([]);
    await expect(readNpmDependencyInventory(root)).rejects.toMatchObject({
      code: 'DEPENDENCY_INVENTORY_INCOMPLETE'
    });
  });

  it('rejects unsupported pnpm formats and duplicate or metadata-free Yarn locks', async () => {
    const pnpm = await fixture();
    await writeFile(
      path.join(pnpm, 'pnpm-lock.yaml'),
      "lockfileVersion: '10.0'\nimporters: {'.': {}}\npackages: {}\n"
    );
    await expect(readNpmDependencyGraph(pnpm)).rejects.toThrow(
      'pnpm lockfile version is unsupported'
    );

    const duplicateYarn = await fixture();
    await writeFile(
      path.join(duplicateYarn, 'package.json'),
      JSON.stringify({ name: 'root', version: '1.0.0' })
    );
    await writeFile(
      path.join(duplicateYarn, 'yarn.lock'),
      '# yarn lockfile v1\n\nfoo@^1.0.0:\n  version "1.0.0"\n\nfoo@^1.0.0:\n  version "1.1.0"\n'
    );
    await expect(readNpmDependencyGraph(duplicateYarn)).rejects.toThrow(
      'Yarn classic lockfile has duplicate descriptors'
    );

    const missingMetadata = await fixture();
    await writeFile(
      path.join(missingMetadata, 'package.json'),
      JSON.stringify({ name: 'root', version: '1.0.0' })
    );
    await writeFile(
      path.join(missingMetadata, 'yarn.lock'),
      'foo@npm:^1.0.0:\n  version: 1.0.0\n'
    );
    await expect(readNpmDependencyGraph(missingMetadata)).rejects.toThrow(
      'Yarn Berry lockfile metadata is missing or invalid'
    );
  });
});
