import { mkdtemp, rm, writeFile } from 'node:fs/promises';
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
  ] as const)('detects %s and maps its lockfile', async (file, manager, lockfile) => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-manager-'));

    try {
      await writeFile(path.join(root, file), '', 'utf8');
      expect(await detectPackageManager(root)).toBe(manager);
      expect(packageManagerLockfile(manager)).toBe(lockfile);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('fails closed to unknown when no supported lockfile exists', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-manager-empty-'));

    try {
      expect(await detectPackageManager(root)).toBe('unknown');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('warns when multiple package-manager lockfiles coexist and keeps explicit precedence', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-manager-conflict-'));
    const warnings: string[] = [];

    try {
      await Promise.all([
        writeFile(path.join(root, 'pnpm-lock.yaml'), '', 'utf8'),
        writeFile(path.join(root, 'yarn.lock'), '', 'utf8'),
        writeFile(path.join(root, 'package-lock.json'), '', 'utf8')
      ]);

      expect(await detectPackageManager(root, (message) => warnings.push(message))).toBe('pnpm');
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain('multiple package-manager lockfiles');
      expect(warnings[0]).toContain('pnpm-lock.yaml, yarn.lock, package-lock.json');
      expect(warnings[0]).toContain('pnpm > yarn > npm');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
