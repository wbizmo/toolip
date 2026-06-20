import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createScannerContext } from '../src/core/scanner-context.js';

describe('createScannerContext', () => {
  it('creates a project scan context with profile and file summary', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-context-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            react: '^19.0.0'
          },
          devDependencies: {
            typescript: '^5.0.0'
          }
        })
      );

      await writeFile(path.join(root, 'package-lock.json'), '{}');
      await writeFile(path.join(root, 'index.ts'), 'export const app = true;');

      const context = await createScannerContext(root);

      expect(context.profile.hasTypeScript).toBe(true);
      expect(context.profile.hasReact).toBe(true);
      expect(context.summary.totalFiles).toBe(3);
      expect(context.summary.extensions.json).toBe(2);
      expect(context.summary.extensions.ts).toBe(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
