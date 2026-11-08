import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  readNpmDependencyGraph,
  readNpmDependencyInventory
} from '../../src/core/dependencies/inventory.js';

const roots: string[] = [];

async function fixture(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-lock-resolver-'));
  roots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

describe('pnpm and Yarn exact dependency graphs', () => {
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
      integrity: sha512-ZGly
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
      integrity: 'sha512-ZGly'
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
  integrity sha512-Zm9v
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
      integrity: 'sha512-Zm9v'
    });
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: foo?.id,
        to: child?.id,
        requirement: '^2.0.0'
      })
    );
  });

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
