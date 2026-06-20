import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildDependencyTree } from '../src/core/dependency-tree.js';

describe('buildDependencyTree', () => {
  it('builds a direct dependency tree summary', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-tree-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            express: '^5.0.0'
          },
          devDependencies: {
            typescript: '^5.0.0'
          }
        })
      );

      const tree = await buildDependencyTree(root);

      expect(tree.summary.direct).toBe(2);
      expect(tree.summary.maxDepth).toBe(1);
      expect(tree.dependencies.map((dependency) => dependency.name)).toContain('express');
      expect(tree.dependencies.map((dependency) => dependency.name)).toContain('typescript');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
