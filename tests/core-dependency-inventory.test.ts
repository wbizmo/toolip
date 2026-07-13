import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { readNpmDependencyInventory } from '../src/core/dependencies/inventory.js';

describe('npm dependency inventory', () => {
  it('reads direct and transitive entries', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-inventory-'));
    try {
      await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'fixture', version: '1.0.0' },
          'node_modules/direct-package': { version: '2.0.0' },
          'node_modules/direct-package/node_modules/transitive-package': { version: '3.0.0', dev: true }
        }
      }));

      const inventory = await readNpmDependencyInventory(root);
      expect(inventory).toEqual([
        expect.objectContaining({ name: 'direct-package', direct: true }),
        expect.objectContaining({ name: 'transitive-package', direct: false, development: true })
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
