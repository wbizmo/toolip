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
import {
  describe,
  expect,
  it
} from 'vitest';
import { GitHistorySecretAnalyzer } from '../../src/analyzers/git-history/analyzer.js';

const execFileAsync = promisify(execFile);

async function configureGit(
  root: string
): Promise<void> {
  await execFileAsync(
    'git',
    ['init'],
    {
      cwd: root
    }
  );

  await execFileAsync(
    'git',
    [
      'config',
      'user.email',
      'test@example.com'
    ],
    {
      cwd: root
    }
  );

  await execFileAsync(
    'git',
    [
      'config',
      'user.name',
      'Toolip Test'
    ],
    {
      cwd: root
    }
  );
}

async function commitAll(
  root: string,
  message: string
): Promise<void> {
  await execFileAsync(
    'git',
    ['add', '.'],
    {
      cwd: root
    }
  );

  await execFileAsync(
    'git',
    ['commit', '-m', message],
    {
      cwd: root
    }
  );
}

describe('GitHistorySecretAnalyzer', () => {
  it('keeps genuine historical credentials critical', async () => {
    const root = await mkdtemp(
      path.join(
        os.tmpdir(),
        'toolip-git-history-real-'
      )
    );

    try {
      await configureGit(root);

      await writeFile(
        path.join(root, 'config.ts'),
        'const token = "ghp_123456789012345678901234567890123456";\n'
      );

      await commitAll(root, 'add credential');

      await writeFile(
        path.join(root, 'config.ts'),
        'const token = process.env.GITHUB_TOKEN;\n'
      );

      await commitAll(root, 'remove credential');

      const result =
        await new GitHistorySecretAnalyzer(
          20
        ).analyze({
          root
        });

      const finding = result.findings.find(
        (item) =>
          item.ruleId === 'TLP-GIT-101'
      );

      expect(finding).toBeDefined();
      expect(finding?.severity).toBe(
        'critical'
      );
      expect(
        finding?.metadata?.testFixture
      ).toBe(false);
      expect(
        finding?.evidence?.[0]?.summary
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

  it('downgrades historical password fixtures in tests', async () => {
    const root = await mkdtemp(
      path.join(
        os.tmpdir(),
        'toolip-git-history-fixture-'
      )
    );

    try {
      await configureGit(root);

      await mkdir(
        path.join(root, 'tests'),
        {
          recursive: true
        }
      );

      await writeFile(
        path.join(
          root,
          'tests',
          'validation.test.ts'
        ),
        `
const user = {
  password: "strong-password"
};
`
      );

      await commitAll(root, 'add test fixture');

      const result =
        await new GitHistorySecretAnalyzer(
          20
        ).analyze({
          root
        });

      const finding = result.findings.find(
        (item) =>
          item.ruleId === 'TLP-GIT-105'
      );

      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('low');
      expect(finding?.confidence).toBe(
        'medium'
      );
      expect(finding?.title).toContain(
        'Potential historical test fixture'
      );
      expect(finding?.location?.file).toBe(
        'tests/validation.test.ts'
      );
      expect(
        finding?.metadata?.testFixture
      ).toBe(true);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('recognizes __tests__ and spec files', async () => {
    const root = await mkdtemp(
      path.join(
        os.tmpdir(),
        'toolip-git-history-test-paths-'
      )
    );

    try {
      await configureGit(root);

      await mkdir(
        path.join(root, 'src', '__tests__'),
        {
          recursive: true
        }
      );

      await writeFile(
        path.join(
          root,
          'src',
          '__tests__',
          'auth.spec.ts'
        ),
        'const password = "fixture-password";\n'
      );

      await commitAll(root, 'add spec fixture');

      const result =
        await new GitHistorySecretAnalyzer(
          20
        ).analyze({
          root
        });

      expect(
        result.findings.some(
          (finding) =>
            finding.severity === 'low' &&
            finding.metadata?.testFixture ===
              true
        )
      ).toBe(true);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });
});
