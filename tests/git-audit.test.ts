import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runGitAudit } from '../src/core/git-audit.js';
import { runPreCommit } from '../src/core/pre-commit.js';
import { installPreCommitHook } from '../src/core/hooks.js';

describe('git security', () => {
  it('detects weak gitignore and dangerous files', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-git-audit-'));

    try {
      await writeFile(path.join(root, '.gitignore'), 'node_modules\n');
      await writeFile(path.join(root, '.env'), 'SECRET=value');
      await writeFile(path.join(root, 'server.pem'), 'PRIVATE KEY');
      await writeFile(path.join(root, 'package.json'), '{}');

      const result = await runGitAudit(root);

      expect(result.summary.gitignorePresent).toBe(true);
      expect(result.summary.envIgnored).toBe(false);
      expect(result.findings.some((finding) => finding.id.includes('ENV-NOT-IGNORED'))).toBe(true);
      expect(result.findings.some((finding) => finding.id.includes('PEM-FILE'))).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('blocks pre-commit on high or critical findings', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-precommit-'));

    try {
      await writeFile(path.join(root, 'package.json'), '{}');
      await writeFile(path.join(root, '.gitignore'), 'node_modules\n');
      await writeFile(path.join(root, 'index.ts'), 'const password = "supersecretpassword";');

      const result = await runPreCommit(root);

      expect(result.passed).toBe(false);
      expect(result.summary.blocking).toBeGreaterThan(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('installs a pre-commit hook', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-hook-'));

    try {
      await mkdir(path.join(root, '.git'), { recursive: true });

      const hookPath = await installPreCommitHook(root);

      expect(hookPath).toContain('pre-commit');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
