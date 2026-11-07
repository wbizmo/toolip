import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  detectPackageManager,
  packageManagerLockfile
} from '../../src/core/package-manager.js';

describe('package manager detection', () => {
  it.each([
    ['package-lock.json', 'npm', 'package-lock.json'],
    ['pnpm-lock.yaml', 'pnpm', 'pnpm-lock.yaml'],
    ['yarn.lock', 'yarn', 'yarn.lock']
  ] as const)(
    'detects %s and maps its lockfile',
    async (file, manager, lockfile) => {
      const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-manager-'));

      try {
        await writeFile(path.join(root, file), '', 'utf8');
        expect(await detectPackageManager(root)).toBe(manager);
        expect(packageManagerLockfile(manager)).toBe(lockfile);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );

  it('fails closed to unknown when no supported lockfile exists', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-manager-empty-'));

    try {
      expect(await detectPackageManager(root)).toBe('unknown');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('fails closed when multiple package-manager lockfiles make selection ambiguous', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-manager-conflict-')
    );
    const warnings: string[] = [];

    try {
      await Promise.all([
        writeFile(path.join(root, 'pnpm-lock.yaml'), '', 'utf8'),
        writeFile(path.join(root, 'yarn.lock'), '', 'utf8'),
        writeFile(path.join(root, 'package-lock.json'), '', 'utf8')
      ]);

      expect(
        await detectPackageManager(root, (message) => warnings.push(message))
      ).toBe('unknown');
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain('multiple package-manager lockfiles');
      expect(warnings[0]).toContain(
        'pnpm-lock.yaml, yarn.lock, package-lock.json'
      );
      expect(warnings[0]).toContain('selection is ambiguous');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('fails closed when a package-manager lockfile is a symlink', async () => {
    if (process.platform === 'win32') return;
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-manager-symlink-')
    );
    const outside = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-manager-outside-')
    );
    const warnings: string[] = [];
    try {
      await writeFile(
        path.join(outside, 'pnpm-lock.yaml'),
        'lockfileVersion: 9.0'
      );
      await symlink(
        path.join(outside, 'pnpm-lock.yaml'),
        path.join(root, 'pnpm-lock.yaml')
      );
      expect(
        await detectPackageManager(root, (warning) => warnings.push(warning))
      ).toBe('unknown');
      expect(warnings[0]).toContain('not a regular file');
    } finally {
      await Promise.all([
        rm(root, { recursive: true, force: true }),
        rm(outside, { recursive: true, force: true })
      ]);
    }
  });
});
