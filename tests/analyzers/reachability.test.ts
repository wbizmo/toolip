import { createHash } from 'node:crypto';
import {
  access,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ReachabilityAnalyzer } from '../../src/analyzers/reachability/reachability-analyzer.js';

const strongIntegrity = `sha512-${Buffer.alloc(64, 0x5a).toString('base64')}`;

describe('ReachabilityAnalyzer', () => {
  it('marks imported packages as reachable', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-reachability-'));

    try {
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
                express: '^5.0.0',
                'unused-package': '^1.0.0'
              }
            },
            'node_modules/express': {
              version: '5.0.0'
            },
            'node_modules/unused-package': {
              version: '1.0.0'
            }
          }
        })
      );
      await mkdir(path.join(root, 'node_modules/express'), { recursive: true });
      await writeFile(
        path.join(root, 'node_modules/express/package.json'),
        JSON.stringify({ name: 'express', version: '5.0.0', main: 'index.js' })
      );
      await writeFile(
        path.join(root, 'node_modules/express/index.js'),
        'module.exports = {};'
      );

      const source = `
import express from 'express';

const app = express();
`;
      await writeFile(path.join(root, 'server.ts'), source);

      const result = await new ReachabilityAnalyzer().analyze({
        root
      });

      const packages = result.metadata?.packages as Array<{
        packageName: string;
        state: string;
      }>;

      expect(
        packages.find((item) => item.packageName === 'express')?.state
      ).toBe('reachable');

      expect(
        packages.find((item) => item.packageName === 'unused-package')?.state
      ).toBe('unknown');

      const reachableFinding = result.findings.find(
        (finding) => finding.ruleId === 'TLP-REACH-001'
      );
      expect(reachableFinding?.metadata?.sourceProvenance).toMatchObject([
        {
          path: 'server.ts',
          sha256: createHash('sha256').update(source).digest('hex'),
          bytes: Buffer.byteLength(source),
          discoverySnapshot: { size: Buffer.byteLength(source) },
          readSnapshot: { size: Buffer.byteLength(source) }
        }
      ]);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('resolves duplicate package versions to the exact workspace installation', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-duplicates-')
    );
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'packages/a': {
              name: 'workspace-a',
              version: '1.0.0',
              dependencies: { shared: '1.0.0' }
            },
            'packages/b': {
              name: 'workspace-b',
              version: '1.0.0',
              dependencies: { shared: '2.0.0' }
            },
            'packages/a/node_modules/shared': { version: '1.0.0' },
            'packages/b/node_modules/shared': { version: '2.0.0' }
          }
        })
      );
      await mkdir(path.join(root, 'packages/a/node_modules/shared'), {
        recursive: true
      });
      await mkdir(path.join(root, 'packages/b/node_modules/shared'), {
        recursive: true
      });
      await writeFile(
        path.join(root, 'packages/a/package.json'),
        JSON.stringify({ name: 'workspace-a' })
      );
      await writeFile(
        path.join(root, 'packages/b/package.json'),
        JSON.stringify({ name: 'workspace-b' })
      );
      await writeFile(
        path.join(root, 'packages/a/node_modules/shared/package.json'),
        JSON.stringify({ name: 'shared', version: '1.0.0', main: 'index.js' })
      );
      await writeFile(
        path.join(root, 'packages/a/node_modules/shared/index.js'),
        'module.exports = 1;'
      );
      await writeFile(
        path.join(root, 'packages/b/node_modules/shared/package.json'),
        JSON.stringify({ name: 'shared', version: '2.0.0', main: 'index.js' })
      );
      await writeFile(
        path.join(root, 'packages/b/node_modules/shared/index.js'),
        'module.exports = 2;'
      );
      await writeFile(
        path.join(root, 'packages/a/entry.ts'),
        "import shared from 'shared'; void shared;\n"
      );

      const result = await new ReachabilityAnalyzer().analyze({ root });
      const packages = result.metadata?.packages as Array<{
        packageId: string;
        packageName: string;
        packageVersion: string;
        state: string;
        installPath: string;
      }>;
      const versions = packages.filter((item) => item.packageName === 'shared');

      expect(versions).toHaveLength(2);
      expect(
        versions.find((item) => item.packageVersion === '1.0.0')
      ).toMatchObject({
        state: 'reachable',
        installPath: 'packages/a/node_modules/shared'
      });
      expect(
        versions.find((item) => item.packageVersion === '2.0.0')
      ).toMatchObject({
        state: 'not-observed',
        installPath: 'packages/b/node_modules/shared'
      });
      expect(new Set(versions.map((item) => item.packageId)).size).toBe(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('maps pnpm symlink resolution to its exact locked store instance', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-pnpm-')
    );
    try {
      await writeFile(
        path.join(root, 'pnpm-lock.yaml'),
        `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      shared:
        specifier: 1.0.0
        version: 1.0.0
packages:
  shared@1.0.0:
    resolution:
      integrity: ${strongIntegrity}
snapshots:
  shared@1.0.0: {}
`
      );
      const storePath = path.join(
        root,
        'node_modules/.pnpm/shared@1.0.0/node_modules/shared'
      );
      await mkdir(storePath, { recursive: true });
      await mkdir(path.join(root, 'node_modules'), { recursive: true });
      await symlink(
        '.pnpm/shared@1.0.0/node_modules/shared',
        path.join(root, 'node_modules/shared'),
        'dir'
      );
      await writeFile(
        path.join(storePath, 'package.json'),
        JSON.stringify({ name: 'shared', version: '1.0.0', main: 'index.js' })
      );
      await writeFile(path.join(storePath, 'index.js'), 'module.exports = 1;');
      await writeFile(
        path.join(root, 'entry.ts'),
        "import shared from 'shared'; void shared;\n"
      );

      const result = await new ReachabilityAnalyzer().analyze({ root });
      const packages = result.metadata?.packages as Array<{
        packageId: string;
        packageName: string;
        packageVersion: string;
        state: string;
        installPath: string;
      }>;

      expect(packages).toEqual([
        expect.objectContaining({
          packageId: 'pnpm:shared@1.0.0',
          packageName: 'shared',
          packageVersion: '1.0.0',
          state: 'reachable',
          installPath: 'node_modules/.pnpm/shared@1.0.0/node_modules/shared'
        })
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('maps Yarn node_modules resolution to its exact locked instance', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-yarn-')
    );
    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({ name: 'fixture', dependencies: { shared: '^1.0.0' } })
      );
      await writeFile(
        path.join(root, 'yarn.lock'),
        `# yarn lockfile v1

shared@^1.0.0:
  version "1.2.0"
  resolved "https://registry.npmjs.org/shared/-/shared-1.2.0.tgz"
  integrity ${strongIntegrity}
`
      );
      await mkdir(path.join(root, 'node_modules/shared'), { recursive: true });
      await writeFile(
        path.join(root, 'node_modules/shared/package.json'),
        JSON.stringify({ name: 'shared', version: '1.2.0', main: 'index.js' })
      );
      await writeFile(
        path.join(root, 'node_modules/shared/index.js'),
        'module.exports = 1;'
      );
      await writeFile(path.join(root, 'entry.ts'), "import 'shared';\n");

      const result = await new ReachabilityAnalyzer().analyze({ root });
      const packages = result.metadata?.packages as Array<{
        packageId: string;
        packageName: string;
        packageVersion: string;
        state: string;
        direct: boolean;
      }>;
      expect(packages).toHaveLength(1);
      expect(packages[0]).toMatchObject({
        packageName: 'shared',
        packageVersion: '1.2.0',
        installPath: 'node_modules/shared',
        state: 'reachable',
        direct: true
      });
      expect(packages[0]?.packageId).toMatch(/^yarn:shared@1\.2\.0#/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks unresolved computed dynamic imports as unknown for installed packages', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-dynamic-')
    );
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: { first: '1.0.0', second: '1.0.0' }
            },
            'node_modules/first': { version: '1.0.0' },
            'node_modules/second': { version: '1.0.0' }
          }
        })
      );
      for (const name of ['first', 'second']) {
        await mkdir(path.join(root, 'node_modules', name), { recursive: true });
        await writeFile(
          path.join(root, 'node_modules', name, 'package.json'),
          JSON.stringify({ name, version: '1.0.0', main: 'index.js' })
        );
        await writeFile(
          path.join(root, 'node_modules', name, 'index.js'),
          'module.exports = 1;'
        );
      }
      await writeFile(
        path.join(root, 'entry.ts'),
        "const target = process.env.MODULE; void import('./modules/' + target);\n"
      );

      const result = await new ReachabilityAnalyzer().analyze({ root });
      const packages = result.metadata?.packages as Array<{
        packageName: string;
        state: string;
      }>;
      expect(
        packages
          .filter((item) => ['first', 'second'].includes(item.packageName))
          .map((item) => item.state)
      ).toEqual(['unknown', 'unknown']);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not attribute an import to a stale installed version that disagrees with the lockfile', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-stale-instance-')
    );
    try {
      await mkdir(path.join(root, 'node_modules', 'example'), {
        recursive: true
      });
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'node_modules/example': { version: '1.0.0' }
          }
        })
      );
      await writeFile(
        path.join(root, 'node_modules/example/package.json'),
        JSON.stringify({ name: 'example', version: '2.0.0', main: 'index.js' })
      );
      await writeFile(
        path.join(root, 'node_modules/example/index.js'),
        'module.exports = true;'
      );
      await writeFile(path.join(root, 'entry.ts'), "import 'example';\n");

      const result = await new ReachabilityAnalyzer().analyze({ root });
      const packages = result.metadata?.packages as Array<{
        packageName: string;
        packageVersion: string;
        state: string;
      }>;
      expect(packages).toContainEqual(
        expect.objectContaining({
          packageName: 'example',
          packageVersion: '1.0.0',
          state: 'unknown'
        })
      );
      expect(result.warnings).toContainEqual(
        expect.stringContaining('dependency-installed-identity-mismatch:')
      );
      expect(result.findings).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not follow an installed package symlink outside the project root', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-symlink-')
    );
    const outside = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-outside-')
    );
    try {
      await mkdir(path.join(root, 'node_modules'), { recursive: true });
      await mkdir(path.join(outside, 'evil'), { recursive: true });
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'node_modules/evil': { version: '1.0.0' }
          }
        })
      );
      await writeFile(
        path.join(outside, 'evil/package.json'),
        JSON.stringify({ name: 'evil', version: '1.0.0', main: 'index.js' })
      );
      await writeFile(
        path.join(outside, 'evil/index.js'),
        'module.exports = true;'
      );
      try {
        await symlink(
          path.join(outside, 'evil'),
          path.join(root, 'node_modules/evil'),
          'junction'
        );
      } catch (error) {
        if (
          error &&
          typeof error === 'object' &&
          'code' in error &&
          ['EPERM', 'EACCES', 'ENOTSUP', 'ENOSYS'].includes(String(error.code))
        )
          return;
        throw error;
      }
      await writeFile(path.join(root, 'entry.ts'), "import 'evil';\n");

      const result = await new ReachabilityAnalyzer().analyze({ root });
      const packages = result.metadata?.packages as Array<{
        packageName: string;
        state: string;
      }>;
      expect(packages.find((item) => item.packageName === 'evil')?.state).toBe(
        'unknown'
      );
      expect(result.findings).toHaveLength(0);
    } finally {
      await Promise.all([
        rm(root, { recursive: true, force: true }),
        rm(outside, { recursive: true, force: true })
      ]);
    }
  });

  it('resolves Yarn PnP imports through exact workspace peer graphs without loading PnP code', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-yarn-pnp-')
    );
    const marker = path.join(root, 'pnp-executed');
    try {
      await mkdir(path.join(root, 'packages/app-a/src'), { recursive: true });
      await mkdir(path.join(root, 'packages/app-b/src'), { recursive: true });
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          name: 'fixture',
          workspaces: ['packages/*']
        })
      );
      await writeFile(
        path.join(root, 'packages/app-a/package.json'),
        JSON.stringify({
          name: 'app-a',
          version: '1.0.0',
          dependencies: { shared: '^1.0.0' }
        })
      );
      await writeFile(
        path.join(root, 'packages/app-b/package.json'),
        JSON.stringify({
          name: 'app-b',
          version: '1.0.0',
          dependencies: { shared: '^2.0.0' }
        })
      );
      await writeFile(
        path.join(root, 'yarn.lock'),
        `__metadata:
  version: 8

"shared@npm:^1.0.0":
  version: 1.2.0
  resolution: "shared@npm:1.2.0"

"shared@npm:^2.0.0":
  version: 2.3.0
  resolution: "shared@npm:2.3.0"
`
      );
      for (const [directory, version] of [
        ['shared-v1', '1.2.0'],
        ['shared-v2', '2.3.0']
      ] as const) {
        const packageDirectory = path.join(
          root,
          '.yarn',
          'unplugged',
          directory,
          'node_modules',
          'shared'
        );
        await mkdir(packageDirectory, { recursive: true });
        await writeFile(
          path.join(packageDirectory, 'package.json'),
          JSON.stringify({ name: 'shared', version })
        );
      }
      const pnpState: {
        packageRegistryData: Array<
          [
            string,
            Array<
              [
                string,
                {
                  packageLocation: string;
                  packageDependencies: Array<[string, string]>;
                }
              ]
            >
          ]
        >;
      } = {
        packageRegistryData: [
          [
            'fixture',
            [
              [
                'workspace:.',
                {
                  packageLocation: './',
                  packageDependencies: []
                }
              ]
            ]
          ],
          [
            'app-a',
            [
              [
                'workspace:packages/app-a',
                {
                  packageLocation: './packages/app-a/',
                  packageDependencies: [['shared', 'npm:1.2.0']]
                }
              ]
            ]
          ],
          [
            'app-b',
            [
              [
                'workspace:packages/app-b',
                {
                  packageLocation: './packages/app-b/',
                  packageDependencies: [['shared', 'npm:2.3.0']]
                }
              ]
            ]
          ],
          [
            'shared',
            [
              [
                'npm:1.2.0',
                {
                  packageLocation:
                    './.yarn/unplugged/shared-v1/node_modules/shared/',
                  packageDependencies: []
                }
              ],
              [
                'npm:2.3.0',
                {
                  packageLocation:
                    './.yarn/unplugged/shared-v2/node_modules/shared/',
                  packageDependencies: []
                }
              ]
            ]
          ]
        ]
      };
      await writeFile(
        path.join(root, '.pnp.cjs'),
        `const RAW_RUNTIME_STATE = ${JSON.stringify(pnpState)};\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ran');\n`
      );
      await writeFile(
        path.join(root, 'packages/app-a/src/index.ts'),
        "import shared from 'shared'; void shared;\n"
      );
      await writeFile(
        path.join(root, 'packages/app-b/src/index.ts'),
        "import shared from 'shared'; void shared;\n"
      );

      const result = await new ReachabilityAnalyzer().analyze({ root });
      const packages = result.metadata?.packages as Array<{
        packageName: string;
        packageVersion: string;
        state: string;
        references: Array<{ file: string }>;
      }>;
      expect(
        packages
          .filter((item) => item.packageName === 'shared')
          .map((item) => ({
            version: item.packageVersion,
            state: item.state,
            file: item.references[0]?.file
          }))
      ).toEqual([
        {
          version: '1.2.0',
          state: 'reachable',
          file: 'packages/app-a/src/index.ts'
        },
        {
          version: '2.3.0',
          state: 'reachable',
          file: 'packages/app-b/src/index.ts'
        }
      ]);
      await expect(access(marker)).rejects.toThrow();

      const sharedV2Manifest = path.join(
        root,
        '.yarn',
        'unplugged',
        'shared-v2',
        'node_modules',
        'shared',
        'package.json'
      );
      await writeFile(
        sharedV2Manifest,
        JSON.stringify({ name: 'shared', version: '9.9.9' })
      );
      const manifestMismatch = await new ReachabilityAnalyzer().analyze({
        root
      });
      const manifestMismatchPackages = manifestMismatch.metadata
        ?.packages as Array<{
        packageName: string;
        packageVersion: string;
        state: string;
      }>;
      expect(
        manifestMismatchPackages.find(
          (item) =>
            item.packageName === 'shared' && item.packageVersion === '2.3.0'
        )?.state
      ).toBe('unknown');
      await writeFile(
        sharedV2Manifest,
        JSON.stringify({ name: 'shared', version: '2.3.0' })
      );

      const sharedV1 = pnpState.packageRegistryData
        .find(([name]) => name === 'shared')?.[1]
        .find(([reference]) => reference === 'npm:1.2.0')?.[1];
      if (!sharedV1) throw new Error('shared v1 PnP fixture is missing');
      sharedV1.packageLocation = '../../outside/shared';
      await writeFile(
        path.join(root, '.pnp.cjs'),
        `const RAW_RUNTIME_STATE = ${JSON.stringify(pnpState)};\n`
      );
      const escaped = await new ReachabilityAnalyzer().analyze({ root });
      const escapedPackages = escaped.metadata?.packages as Array<{
        packageName: string;
        packageVersion: string;
        state: string;
      }>;
      expect(
        escapedPackages.find(
          (item) =>
            item.packageName === 'shared' && item.packageVersion === '1.2.0'
        )?.state
      ).toBe('unknown');
      expect(escaped.warnings).toContainEqual(
        expect.stringContaining('yarn-pnp-package-identity-unresolved:')
      );

      const outside = await mkdtemp(
        path.join(os.tmpdir(), 'toolip-reachability-pnp-outside-')
      );
      try {
        const sharedV1Directory = path.join(
          root,
          '.yarn',
          'unplugged',
          'shared-v1',
          'node_modules',
          'shared'
        );
        await rm(sharedV1Directory, { recursive: true, force: true });
        await symlink(
          outside,
          sharedV1Directory,
          process.platform === 'win32' ? 'junction' : 'dir'
        );
        sharedV1.packageLocation =
          './.yarn/unplugged/shared-v1/node_modules/shared/';
        await writeFile(
          path.join(root, '.pnp.cjs'),
          `const RAW_RUNTIME_STATE = ${JSON.stringify(pnpState)};\n`
        );
        const symlinkEscape = await new ReachabilityAnalyzer().analyze({
          root
        });
        const symlinkEscapePackages = symlinkEscape.metadata
          ?.packages as Array<{
          packageName: string;
          packageVersion: string;
          state: string;
        }>;
        expect(
          symlinkEscapePackages.find(
            (item) =>
              item.packageName === 'shared' && item.packageVersion === '1.2.0'
          )?.state
        ).toBe('unknown');
      } finally {
        await rm(
          path.join(
            root,
            '.yarn',
            'unplugged',
            'shared-v1',
            'node_modules',
            'shared'
          ),
          { recursive: true, force: true }
        );
        await rm(outside, { recursive: true, force: true });
      }

      sharedV1.packageLocation =
        './.yarn/cache/shared-npm-1.2.0.zip/node_modules/shared/';
      const cachePath = path.join(root, '.yarn', 'cache');
      await mkdir(cachePath, { recursive: true });
      await writeFile(
        path.join(cachePath, 'shared-npm-1.2.0.zip'),
        'not a verified Yarn archive'
      );
      await writeFile(
        path.join(root, '.pnp.cjs'),
        `const RAW_RUNTIME_STATE = ${JSON.stringify(pnpState)};\n`
      );
      const archiveLocation = await new ReachabilityAnalyzer().analyze({
        root
      });
      const archivePackages = archiveLocation.metadata?.packages as Array<{
        packageName: string;
        packageVersion: string;
        state: string;
      }>;
      expect(
        archivePackages.find(
          (item) =>
            item.packageName === 'shared' && item.packageVersion === '1.2.0'
        )?.state
      ).toBe('unknown');
      expect(archiveLocation.warnings).toContainEqual(
        expect.stringContaining('yarn-pnp-archive-content-unverified:')
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('binds Yarn PnP aliases to the exact target locator and installed identity', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-yarn-alias-')
    );
    const marker = path.join(root, 'pnp-executed');
    try {
      const packageDirectory = path.join(
        root,
        '.yarn/unplugged/react18/node_modules/react'
      );
      await mkdir(packageDirectory, { recursive: true });
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          name: 'fixture',
          version: '1.0.0',
          dependencies: { 'react18-alias': 'npm:react@18.2.0' }
        })
      );
      await writeFile(
        path.join(root, 'yarn.lock'),
        `__metadata:\n  version: 8\n\n"react18-alias@npm:react@18.2.0":\n  version: 18.2.0\n  resolution: "react@npm:18.2.0"\n  checksum: 10c0/abc123\n  languageName: node\n  linkType: hard\n`
      );
      await writeFile(
        path.join(packageDirectory, 'package.json'),
        JSON.stringify({ name: 'react', version: '18.2.0' })
      );
      const pnpState = {
        packageRegistryData: [
          [
            'fixture',
            [
              [
                'workspace:.',
                {
                  packageLocation: './',
                  packageDependencies: [
                    ['react18-alias', ['react', 'npm:18.2.0']]
                  ]
                }
              ]
            ]
          ],
          [
            'react',
            [
              [
                'npm:18.2.0',
                {
                  packageLocation:
                    './.yarn/unplugged/react18/node_modules/react/',
                  packageDependencies: []
                }
              ]
            ]
          ]
        ]
      };
      await writeFile(
        path.join(root, '.pnp.cjs'),
        `const RAW_RUNTIME_STATE = ${JSON.stringify(pnpState)};\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ran');\n`
      );
      await writeFile(
        path.join(root, 'entry.ts'),
        "import React from 'react18-alias'; void React;\n"
      );

      const result = await new ReachabilityAnalyzer().analyze({ root });
      const packages = result.metadata?.packages as Array<{
        packageName: string;
        packageVersion: string;
        installPath: string;
        state: string;
      }>;
      expect(packages).toContainEqual(
        expect.objectContaining({
          packageName: 'react',
          packageVersion: '18.2.0',
          installPath: '.yarn/unplugged/react18/node_modules/react',
          state: 'reachable'
        })
      );
      await expect(access(marker)).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
