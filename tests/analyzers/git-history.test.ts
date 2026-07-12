import {
  mkdtemp,
  rm,
  writeFile
} from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { GitHistorySecretAnalyzer } from '../../src/analyzers/git-history/analyzer.js';

const execFileAsync = promisify(execFile);

describe('GitHistorySecretAnalyzer', () => {
  it('finds secrets introduced in previous commits', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-git-history-')
    );

    try {
      await execFileAsync(
        'git',
        ['init'],
        {
          cwd: root
        }
      );

      await execFileAsync(
        'git',
        ['config', 'user.email', 'test@example.com'],
        {
          cwd: root
        }
      );

      await execFileAsync(
        'git',
        ['config', 'user.name', 'Toolip Test'],
        {
          cwd: root
        }
      );

      await writeFile(
        path.join(root, 'secret.txt'),
        'token=ghp_123456789012345678901234567890123456\n'
      );

      await execFileAsync(
        'git',
        ['add', '.'],
        {
          cwd: root
        }
      );

      await execFileAsync(
        'git',
        ['commit', '-m', 'add fixture'],
        {
          cwd: root
        }
      );

      await writeFile(
        path.join(root, 'secret.txt'),
        'removed\n'
      );

      await execFileAsync(
        'git',
        ['add', '.'],
        {
          cwd: root
        }
      );

      await execFileAsync(
        'git',
        ['commit', '-m', 'remove fixture'],
        {
          cwd: root
        }
      );

      const result =
        await new GitHistorySecretAnalyzer(
          20
        ).analyze({
          root
        });

      expect(
        result.findings.some(
          (finding) =>
            finding.ruleId === 'TLP-GIT-101'
        )
      ).toBe(true);

      expect(
        result.findings[0]?.evidence?.[0]
          ?.summary
      ).not.toContain(
        '123456789012345678901234567890'
      );
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });
});
