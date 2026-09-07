import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runGitAudit } from '../src/core/git-audit.js';
import { runPreCommit } from '../src/core/pre-commit.js';
import { installPreCommitHook } from '../src/core/hooks.js';

const execFileAsync = promisify(execFile);

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

  it('blocks staged secrets but ignores unrelated unstaged historical findings', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-precommit-'));

    try {
      await initGit(root);
      await writeFile(path.join(root, 'package.json'), '{}');
      await writeFile(
        path.join(root, '.gitignore'),
        'node_modules\n.env\n*.pem\n'
      );
      await writeFile(
        path.join(root, 'old.ts'),
        'const password = "old-supersecretpassword";\n'
      );
      await execFileAsync('git', ['add', '.'], { cwd: root });
      await execFileAsync('git', ['commit', '-m', 'initial'], { cwd: root });

      await writeFile(path.join(root, 'old.ts'), 'const password = "unstaged-secret-value";\n');
      await writeFile(path.join(root, 'safe.ts'), 'export const safe = true;\n');
      await execFileAsync('git', ['add', 'safe.ts'], { cwd: root });

      const safeResult = await runPreCommit(root);
      expect(safeResult.scope).toBe('staged');
      expect(safeResult.filesConsidered).toBe(1);
      expect(safeResult.passed).toBe(true);
      expect(
        safeResult.findings.some((finding) => finding.location?.file === 'old.ts')
      ).toBe(false);

      await writeFile(
        path.join(root, 'safe.ts'),
        'const password = "new-supersecretpassword";\n'
      );
      await execFileAsync('git', ['add', 'safe.ts'], { cwd: root });

      const blockingResult = await runPreCommit(root);
      expect(blockingResult.passed).toBe(false);
      expect(blockingResult.summary.blocking).toBeGreaterThan(0);
      expect(
        blockingResult.findings.some((finding) => finding.location?.file === 'safe.ts')
      ).toBe(true);

      const fullResult = await runPreCommit(root, { full: true });
      expect(fullResult.scope).toBe('full');
      expect(
        fullResult.findings.some((finding) => finding.location?.file === 'old.ts')
      ).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('preserves existing pre-commit hooks and installs one idempotent local Toolip block', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-hook-'));
    const hooksDir = path.join(root, '.git', 'hooks');
    const hookPath = path.join(hooksDir, 'pre-commit');

    try {
      await mkdir(hooksDir, { recursive: true });
      await writeFile(
        hookPath,
        '#!/bin/sh\necho "existing hook"\n',
        'utf8'
      );

      await installPreCommitHook(root);
      await installPreCommitHook(root);

      const installed = await readFile(hookPath, 'utf8');
      expect(installed).toContain('echo "existing hook"');
      expect(installed).toContain('./node_modules/.bin/toolip pre-commit --path .');
      expect(installed).not.toContain('npx toolip');
      expect(installed.match(/>>> toolip managed pre-commit >>>/g)).toHaveLength(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

async function initGit(root: string): Promise<void> {
  await execFileAsync('git', ['init'], { cwd: root });
  await execFileAsync('git', ['config', 'user.name', 'Toolip Test'], { cwd: root });
  await execFileAsync('git', ['config', 'user.email', 'toolip@example.test'], { cwd: root });
}
