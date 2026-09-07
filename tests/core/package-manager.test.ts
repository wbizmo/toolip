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
});
