import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const repo = path.resolve(import.meta.dirname, '../..');

describe('review-only signed installation candidates', () => {
  it('prints a deterministic POSIX dry-run without downloading or installing', async () => {
    if (process.platform === 'win32') return;
    const dir = await mkdtemp(path.join(os.tmpdir(), 'toolip-install-dry-run-'));
    try {
      const key = path.join(dir, 'trusted.pem');
      await writeFile(key, 'fixture public key, dry-run only\n');
      const result = spawnSync('sh', [
        path.join(repo, 'distribution/install/install.sh'),
        '--version', '3.2.1',
        '--git-sha', 'a'.repeat(40),
        '--public-key', key,
        '--prefix', path.join(dir, 'bin'),
        '--dry-run'
      ], {
        cwd: repo,
        encoding: 'utf8',
        shell: false,
        env: { ...process.env, HOME: dir }
      });
      expect(result.status).toBe(0);
      expect(result.stdout).toContain('No network or filesystem changes');
      expect(result.stdout).toContain('toolip-3.2.1-');
      expect(result.stdout).toContain('release-manifest.json');
      expect(result.stdout).not.toContain('Installed signed');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('requires user-provided public-key anchors and never includes pipe-to-shell shortcuts', async () => {
    const posix = await readFile(
      path.join(repo, 'distribution/install/install.sh'), 'utf8'
    );
    const windows = await readFile(
      path.join(repo, 'distribution/install/install.ps1'), 'utf8'
    );
    for (const source of [posix, windows]) {
      expect(source).toContain('release-manifest.sig');
      expect(source).toContain('release-manifest.json');
      expect(source).toContain('openssl');
      expect(source).not.toMatch(/curl[^\n]*\|\s*(?:sh|bash)/iu);
      expect(source).not.toMatch(/Invoke-Expression\s*\(/iu);
      expect(source).not.toMatch(/\bsudo\s+/iu);
    }
  });
});
