import { describe, expect, it } from 'vitest';
import {
  mkdir,
  mkdtemp,
  rm,
  stat as statTarget,
  symlink,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { walkProjectFiles } from '../src/core/file-walker.js';

describe('walkProjectFiles', () => {
  it('walks files while respecting .toolipignore', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-walk-'));

    try {
      await mkdir(path.join(root, 'src'), { recursive: true });
      await mkdir(path.join(root, 'dist'), { recursive: true });
      await mkdir(path.join(root, 'secrets'), { recursive: true });

      await writeFile(
        path.join(root, 'src', 'index.ts'),
        'console.log("safe");'
      );
      await writeFile(
        path.join(root, 'dist', 'index.js'),
        'console.log("ignored");'
      );
      await writeFile(path.join(root, 'secrets', 'local.txt'), 'ignored');
      await writeFile(path.join(root, '.toolipignore'), 'secrets\n');

      const files = await walkProjectFiles(root);
      const relativePaths = files.map((file) => file.relativePath);

      expect(relativePaths).toContain('.toolipignore');
      expect(relativePaths).toContain('src/index.ts');
      expect(relativePaths).not.toContain('dist/index.js');
      expect(relativePaths).not.toContain('secrets/local.txt');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('reports inaccessible symbolic targets as incomplete discovery', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-walk-link-'));
    const outside = await mkdtemp(path.join(os.tmpdir(), 'toolip-outside-'));
    const link = path.join(root, 'blocked-directory');

    try {
      await writeFile(path.join(outside, 'hidden.ts'), 'const hidden = true;');
      await symlink(outside, link, 'dir');

      await expect(
        walkProjectFiles(root, {
          statTarget: async (target) => {
            if (target === link) {
              throw Object.assign(new Error('permission denied'), {
                code: 'EACCES'
              });
            }
            return statTarget(target);
          }
        })
      ).rejects.toMatchObject({ code: 'SCAN_DISCOVERY_INCOMPLETE' });
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });
});
