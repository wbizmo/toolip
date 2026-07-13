import {
  mkdtemp,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ReachabilityAnalyzer } from '../../src/analyzers/reachability/reachability-analyzer.js';

describe('ReachabilityAnalyzer', () => {
  it('marks imported packages as reachable', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-reachability-')
    );

    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          name: 'fixture',
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0'
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

      await writeFile(
        path.join(root, 'server.ts'),
        `
import express from 'express';

const app = express();
`
      );

      const result = await new ReachabilityAnalyzer().analyze({
        root
      });

      const packages = result.metadata?.packages as Array<{
        packageName: string;
        state: string;
      }>;

      expect(
        packages.find(
          (item) => item.packageName === 'express'
        )?.state
      ).toBe('reachable');

      expect(
        packages.find(
          (item) =>
            item.packageName === 'unused-package'
        )?.state
      ).toBe('possibly-reachable');
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });
});
