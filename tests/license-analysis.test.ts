import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { analyzeLicenses } from '../src/core/license-analysis.js';

describe('analyzeLicenses', () => {
  it('creates license inventory and unknown license findings', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-license-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            axios: '^1.0.0',
            'unknown-package': '^1.0.0'
          }
        })
      );

      const result = await analyzeLicenses(root);

      expect(result.summary.total).toBe(2);
      expect(result.summary.unknown).toBe(1);
      expect(result.summary.distribution.MIT).toBe(1);
      expect(result.findings[0]?.id).toContain('TOOLIP-LICENSE-UNKNOWN');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
