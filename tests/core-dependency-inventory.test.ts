import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  readNpmDependencyGraph,
  readNpmDependencyInventory
} from '../src/core/dependencies/inventory.js';

describe('npm dependency inventory', () => {
  it('derives directness and edges from lock metadata rather than hoisting', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-inventory-'));
    try {
      await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'fixture',
            version: '1.0.0',
            dependencies: {
              'direct-package': '^2.0.0',
              'other-package': '^1.0.0'
            }
          },
          'node_modules/direct-package': {
            version: '2.0.0',
            dependencies: {
              'transitive-package': '^3.0.0',
              duplicated: '^1.0.0'
            }
          },
          'node_modules/transitive-package': {
            version: '3.0.0'
          },
          'node_modules/direct-package/node_modules/duplicated': {
            version: '1.0.0'
          },
          'node_modules/other-package': {
            version: '1.0.0',
            dependencies: {
              duplicated: '^2.0.0'
            }
          },
          'node_modules/other-package/node_modules/duplicated': {
            version: '2.0.0',
            dev: true
          }
        }
      }));

      const inventory = await readNpmDependencyInventory(root);
      const direct = inventory.find((item) => item.name === 'direct-package');
      const hoistedTransitive = inventory.find(
        (item) => item.name === 'transitive-package'
      );
      const duplicates = inventory.filter((item) => item.name === 'duplicated');

      expect(direct?.direct).toBe(true);
      expect(hoistedTransitive).toMatchObject({
        direct: false,
        installPath: 'node_modules/transitive-package'
      });
      expect(duplicates.map((item) => [item.version, item.installPath])).toEqual([
        ['1.0.0', 'node_modules/direct-package/node_modules/duplicated'],
        ['2.0.0', 'node_modules/other-package/node_modules/duplicated']
      ]);

      const graph = await readNpmDependencyGraph(root);
      const directId = direct?.id;
      const transitiveId = hoistedTransitive?.id;

      expect(graph.edges).toContainEqual(
        expect.objectContaining({
          from: directId,
          to: transitiveId,
          name: 'transitive-package'
        })
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('resolves npm workspace link entries to the exact workspace package identity', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-inventory-workspace-'));
    try {
      await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'fixture',
            version: '1.0.0',
            dependencies: {
              '@fixture/workspace-package': 'workspace:*'
            }
          },
          'node_modules/@fixture/workspace-package': {
            resolved: 'packages/workspace-package',
            link: true
          },
          'packages/workspace-package': {
            name: '@fixture/workspace-package',
            version: '1.5.0',
            dependencies: {
              'transitive-package': '^3.0.0'
            }
          },
          'node_modules/transitive-package': {
            version: '3.0.0'
          }
        }
      }));

      const graph = await readNpmDependencyGraph(root);
      const workspace = graph.packages.find(
        (item) => item.name === '@fixture/workspace-package'
      );
      const transitive = graph.packages.find(
        (item) => item.name === 'transitive-package'
      );

      expect(workspace).toMatchObject({
        version: '1.5.0',
        direct: true,
        installPath: 'packages/workspace-package'
      });
      expect(graph.rootDependencies).toContain(workspace?.id);
      expect(graph.edges).toContainEqual(expect.objectContaining({
        from: 'root',
        to: workspace?.id,
        name: '@fixture/workspace-package',
        requirement: 'workspace:*'
      }));
      expect(graph.edges).toContainEqual(expect.objectContaining({
        from: workspace?.id,
        to: transitive?.id,
        name: 'transitive-package'
      }));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
