import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  buildDependencyTree,
  graphSummary
} from '../src/core/dependency-tree.js';

describe('buildDependencyTree', () => {
  it('enqueues high-fan-in reachable nodes once with a vertex-bounded queue', () => {
    const sourceCount = 256;
    const sharedCount = 512;
    const sources = Array.from(
      { length: sourceCount },
      (_, index) => `p${index}`
    );
    const shared = Array.from(
      { length: sharedCount },
      (_, index) => `s${index}`
    );
    const children = new Map<string, readonly string[]>([
      ['root', sources],
      ...sources.map((id) => [id, shared] as const)
    ]);
    const stats = { enqueuedNodes: 0, peakQueueEntries: 0 };

    const summary = graphSummary(children, stats);

    expect(summary).toEqual({
      direct: sourceCount,
      transitive: sharedCount,
      maxDepth: 2
    });
    expect(stats.enqueuedNodes).toBe(sourceCount + sharedCount);
    expect(stats.peakQueueEntries).toBeLessThanOrEqual(
      sourceCount + sharedCount
    );
  });

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
      expect(
        tree.dependencies.find((dependency) => dependency.name === 'typescript')
          ?.type
      ).toBe('devDependency');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('bounds converging graphs and cycles without expanding every dependency path', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-tree-converging-')
    );
    try {
      const layers = 12;
      const lockPackages: Record<string, unknown> = {
        '': {
          dependencies: {
            'layer-0-a': '1.0.0',
            'layer-0-b': '1.0.0'
          }
        }
      };
      for (let layer = 0; layer < layers; layer++) {
        for (const side of ['a', 'b']) {
          const name = `layer-${layer}-${side}`;
          lockPackages[`node_modules/${name}`] = {
            version: '1.0.0',
            ...(layer + 1 < layers
              ? {
                  dependencies: {
                    [`layer-${layer + 1}-a`]: '1.0.0',
                    [`layer-${layer + 1}-b`]: '1.0.0'
                  }
                }
              : { dependencies: { 'layer-0-a': '1.0.0' } })
          };
        }
      }
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({ lockfileVersion: 3, packages: lockPackages })
      );

      const tree = await buildDependencyTree(root);
      let count = 0;
      const stack = [...tree.dependencies];
      let sawReference = false;
      while (stack.length) {
        const item = stack.pop();
        if (!item) continue;
        count++;
        sawReference ||= item.referenceOnly === true;
        stack.push(...item.children);
      }
      expect(tree.summary).toMatchObject({ direct: 2, maxDepth: layers });
      expect(tree.summary.transitive).toBe(layers * 2 - 2);
      expect(count).toBeLessThanOrEqual(layers * 2 + 48);
      expect(sawReference).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('preserves longest dependency depth on converging acyclic graphs', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-tree-converging-dag-')
    );
    try {
      const size = 20;
      const lockPackages: Record<string, unknown> = {
        '': {
          dependencies: {
            'node-0': '1.0.0',
            'node-1': '1.0.0'
          }
        }
      };
      for (let index = 0; index < size; index += 1) {
        const dependencies: Record<string, string> = {};
        for (const offset of [1, 2]) {
          const child = index + offset;
          if (child < size) dependencies[`node-${child}`] = '1.0.0';
        }
        lockPackages[`node_modules/node-${index}`] = {
          version: '1.0.0',
          ...(Object.keys(dependencies).length > 0 ? { dependencies } : {})
        };
      }
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({ lockfileVersion: 3, packages: lockPackages })
      );

      const tree = await buildDependencyTree(root);
      expect(tree.summary).toEqual({
        direct: 2,
        transitive: size - 2,
        maxDepth: size
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
