import { describe, expect, it } from 'vitest';
import {
  mkdir,
  lstat,
  mkdtemp,
  rm,
  stat as statTarget,
  symlink,
  writeFile
} from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import {
  filterIgnoredEntries,
  walkProjectFiles
} from '../src/core/file-walker.js';
import { loadToolipIgnore } from '../src/core/load-toolip-ignore.js';

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
      const toolipIgnore = await loadToolipIgnore(root);

      expect(relativePaths).toContain('.toolipignore');
      expect(relativePaths).toContain('src/index.ts');
      expect(relativePaths).not.toContain('dist/index.js');
      expect(relativePaths).not.toContain('secrets/local.txt');
      expect(
        filterIgnoredEntries(
          ['src/index.ts', 'dist/index.js', 'secrets/local.txt'],
          root,
          toolipIgnore
        )
      ).toEqual(['src/index.ts']);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('filters ignored entries before scheduling metadata inspection', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-walk-prefilter-')
    );
    const ignored = path.join(root, 'ignored.txt');
    let inspected = false;

    try {
      await writeFile(path.join(root, '.toolipignore'), 'ignored.txt\n');
      await writeFile(ignored, 'ignored');

      await expect(
        walkProjectFiles(root, {
          findEntries: async () => ['ignored.txt'],
          lstatEntry: async (entry, options) => {
            inspected = true;
            return lstat(entry, options);
          }
        })
      ).resolves.toEqual([]);
      expect(inspected).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('includes present index-tracked files hidden by local ignore rules when requested', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-walk-tracked-'));
    try {
      await writeFile(path.join(root, '.toolipignore'), 'ignored-loader.orc\n');
      await writeFile(path.join(root, 'ignored-loader.orc'), 'eval(atob(x));');
      await writeFile(path.join(root, 'visible.ts'), 'export {};');
      const git = (args: string[]) =>
        execFileSync('git', ['-C', root, ...args], { stdio: 'ignore' });
      git(['init', '-q']);
      git(['config', 'user.name', 'Toolip Test']);
      git(['config', 'user.email', 'toolip-test@example.invalid']);
      git(['add', '.toolipignore', 'visible.ts']);
      git(['add', '-f', 'ignored-loader.orc']);
      git(['commit', '-qm', 'fixture']);

      await expect(walkProjectFiles(root)).resolves.not.toContainEqual(
        expect.objectContaining({ relativePath: 'ignored-loader.orc' })
      );
      await expect(
        walkProjectFiles(root, { includeTrackedIgnored: true })
      ).resolves.toEqual(
        expect.arrayContaining([
          expect.objectContaining({ relativePath: 'ignored-loader.orc' })
        ])
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('stops streaming entries at the file budget before metadata reads', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-walk-budget-'));
    let inspected = 0;
    try {
      await Promise.all(
        Array.from({ length: 8 }, (_, index) =>
          writeFile(path.join(root, `file-${index}.txt`), 'fixture')
        )
      );
      await expect(
        walkProjectFiles(root, {
          maxFiles: 2,
          lstatEntry: async (entry, options) => {
            inspected += 1;
            return lstat(entry, options);
          }
        })
      ).rejects.toMatchObject({ code: 'SCAN_FILE_LIMIT_EXCEEDED' });
      expect(inspected).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('cancels discovery before starting metadata work', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-walk-cancel-'));
    const controller = new AbortController();
    let inspected = false;
    controller.abort();
    try {
      await expect(
        walkProjectFiles(root, {
          signal: controller.signal,
          findEntries: async () => ['file.ts'],
          lstatEntry: async (entry, options) => {
            inspected = true;
            return lstat(entry, options);
          }
        })
      ).rejects.toMatchObject({ code: 'SCAN_CANCELLED' });
      expect(inspected).toBe(false);
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
      await symlink(
        outside,
        link,
        process.platform === 'win32' ? 'junction' : 'dir'
      );

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

  it.skipIf(process.platform === 'win32')(
    'reports a symbolic target that disappears during discovery as incomplete',
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), 'toolip-walk-missing-link-')
      );
      const target = path.join(root, 'target.ts');
      const link = path.join(root, 'source.ts');

      try {
        await writeFile(target, 'const source = true;');
        await symlink(target, link);

        await expect(
          walkProjectFiles(root, {
            statTarget: async () => {
              throw Object.assign(new Error('target disappeared'), {
                code: 'ENOENT'
              });
            }
          })
        ).rejects.toMatchObject({ code: 'SCAN_DISCOVERY_INCOMPLETE' });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );

  it('ignores symlinked directories matched by directory ignore rules', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-walk-ignore-link-')
    );
    const outside = await mkdtemp(path.join(os.tmpdir(), 'toolip-outside-'));
    const link = path.join(root, 'generated-link');

    try {
      await writeFile(path.join(outside, 'hidden.ts'), 'const hidden = true;');
      await writeFile(path.join(root, '.toolipignore'), 'generated-link/\n');
      await symlink(
        outside,
        link,
        process.platform === 'win32' ? 'junction' : 'dir'
      );

      await expect(walkProjectFiles(root)).resolves.toEqual(
        expect.arrayContaining([
          expect.objectContaining({ relativePath: '.toolipignore' })
        ])
      );
      await expect(walkProjectFiles(root)).resolves.not.toContainEqual(
        expect.objectContaining({ relativePath: 'generated-link' })
      );
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });
});
