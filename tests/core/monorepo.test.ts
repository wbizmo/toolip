import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { discoverWorkspaces } from '../../src/core/monorepo/discover.js';

describe('monorepo discovery', () => {
  it('discovers npm workspaces', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-monorepo-'));

    try {
      await mkdir(path.join(root, 'packages', 'api'), { recursive: true });
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({ workspaces: ['packages/*'] })
      );
      await writeFile(
        path.join(root, 'packages', 'api', 'package.json'),
        JSON.stringify({ name: '@fixture/api', version: '1.0.0' })
      );

      const result = await discoverWorkspaces(root);
      expect(result).toHaveLength(1);
      expect(result[0]?.name).toBe('@fixture/api');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
