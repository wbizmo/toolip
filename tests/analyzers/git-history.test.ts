import {
  mkdir,
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

async function configureGit(root: string): Promise<void> {
  await execFileAsync('git', ['init'], { cwd: root });
  await execFileAsync(
    'git',
    ['config', 'user.email', 'test@example.com'],
    { cwd: root }
  );
  await execFileAsync(
    'git',
    ['config', 'user.name', 'Toolip Test'],
    { cwd: root }
  );
}

async function commitAll(root: string, message: string): Promise<void> {
  await execFileAsync('git', ['add', '.'], { cwd: root });
  await execFileAsync('git', ['commit', '-m', message], { cwd: root });
}

describe('GitHistorySecretAnalyzer', () => {
  it('keeps genuine historical credentials critical without exposing token fragments', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-git-history-real-')
    );
    const secret = 'ghp_123456789012345678901234567890123456';

    try {
      await configureGit(root);
      await writeFile(
        path.join(root, 'config.ts'),
        `const token = "${secret}";\n`
      );
      await commitAll(root, 'add credential');
      await writeFile(
        path.join(root, 'config.ts'),
        'const token = process.env.GITHUB_TOKEN;\n'
      );
      await commitAll(root, 'remove credential');

      const result = await new GitHistorySecretAnalyzer(20).analyze({ root });
      const finding = result.findings.find(
        (item) => item.ruleId === 'TLP-GIT-101'
      );

      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('critical');
      expect(finding?.metadata?.testFixtureCandidate).toBe(false);
      expect(finding?.evidence?.[0]?.summary).not.toContain(secret);
      expect(finding?.evidence?.[0]?.summary).not.toContain('ghp_');
      expect(finding?.evidence?.[0]?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('preserves severity for historical password candidates in tests', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-git-history-fixture-')
    );

    try {
      await configureGit(root);
      await mkdir(path.join(root, 'tests'), { recursive: true });
      await writeFile(
        path.join(root, 'tests', 'validation.test.ts'),
        'const user = { password: "strong-password" };\n'
      );
      await commitAll(root, 'add test fixture');

      const result = await new GitHistorySecretAnalyzer(20).analyze({ root });
      const finding = result.findings.find(
        (item) => item.ruleId === 'TLP-GIT-105'
      );

      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
      expect(finding?.confidence).toBe('medium');
      expect(finding?.title).toContain('Potential historical test fixture');
      expect(finding?.location?.file).toBe('tests/validation.test.ts');
      expect(finding?.metadata?.testFixtureCandidate).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('recognizes __tests__ and spec files without lowering severity', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-git-history-test-paths-')
    );

    try {
      await configureGit(root);
      await mkdir(path.join(root, 'src', '__tests__'), { recursive: true });
      await writeFile(
        path.join(root, 'src', '__tests__', 'auth.spec.ts'),
        'const password = "fixture-password";\n'
      );
      await commitAll(root, 'add spec fixture');

      const result = await new GitHistorySecretAnalyzer(20).analyze({ root });

      expect(
        result.findings.some(
          (finding) =>
            finding.severity === 'high' &&
            finding.metadata?.testFixtureCandidate === true
        )
      ).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('honors an explicit same-line fixture marker', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-git-history-allow-')
    );

    try {
      await configureGit(root);
      await mkdir(path.join(root, 'tests'), { recursive: true });
      await writeFile(
        path.join(root, 'tests', 'fixture.test.ts'),
        'const password = "fixture-password"; // toolip:allow-secret-fixture\n'
      );
      await commitAll(root, 'add explicit fixture');

      const result = await new GitHistorySecretAnalyzer(20).analyze({ root });
      expect(result.findings).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
