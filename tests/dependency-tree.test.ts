import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildDependencyTree } from '../src/core/dependency-tree.js';

describe('buildDependencyTree', () => {
  it('builds resolved direct and transitive relationships', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-tree-'));

    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              dependencies: {
                express: '^5.0.0'
              },
              devDependencies: {
                typescript: '^5.0.0'
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
            },
            'node_modules/typescript': {
              version: '5.9.3',
              dev: true
            }
          }
        })
      );

      const tree = await buildDependencyTree(root);
      const express = tree.dependencies.find(
        (dependency) => dependency.name === 'express'
      );

      expect(tree.summary).toEqual({
        direct: 2,
        transitive: 1,
        maxDepth: 2
      });
      expect(express?.children).toEqual([
        expect.objectContaining({
          name: 'router',
          version: '2.0.0'
        })
      ]);
      expect(tree.dependencies.find(
        (dependency) => dependency.name === 'typescript'
      )?.type).toBe('devDependency');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
