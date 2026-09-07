import {
  mkdir,
  mkdtemp,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { runSecurityDoctor } from '../src/core/security-doctor.js';

describe('secret detection hardening', () => {
  it('reports every same-rule occurrence with unique locations and no secret fragments', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-secret-occurrences-'));
    const first = 'ghp_111111111111111111111111111111111111';
    const second = 'ghp_222222222222222222222222222222222222';

    try {
      await writeFile(path.join(root, 'package.json'), '{}');
      await writeFile(
        path.join(root, 'secrets.ts'),
        `const first = "${first}";\nconst second = "${second}";\nconst password = "abcdefgh";\n`
      );

      const result = await runSecurityDoctor(root);
      const github = result.findings.filter(
        (finding) => finding.ruleId === 'TOOLIP-SECRET-GITHUB-TOKEN'
      );

      expect(github).toHaveLength(2);
      expect(new Set(github.map((finding) => finding.id)).size).toBe(2);
      expect(github.map((finding) => finding.location?.line)).toEqual([1, 2]);

      for (const finding of result.findings.filter(
        (item) => item.category === 'secrets'
      )) {
        const summary = finding.evidence?.[0]?.summary ?? '';
        expect(summary).toMatch(/^\[redacted secret; sha256:[a-f0-9]{12}\]$/);
        expect(summary).not.toContain('ghp_');
        expect(summary).not.toContain('abcdefgh');
        expect(finding.evidence?.[0]?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not lower a real credential merely because it is in a test file', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-secret-test-severity-'));

    try {
      await writeFile(path.join(root, 'package.json'), '{}');
      await writeFile(
        path.join(root, 'auth.test.ts'),
        'const token = "ghp_333333333333333333333333333333333333";\n'
      );

      const result = await runSecurityDoctor(root);
      const finding = result.findings.find(
        (item) => item.ruleId === 'TOOLIP-SECRET-GITHUB-TOKEN'
      );

      expect(finding?.severity).toBe('critical');
      expect(finding?.confidence).toBe('medium');
      expect(finding?.metadata?.testFixtureCandidate).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('supports explicit fixture annotations and collision-resistant instance IDs', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-secret-identities-'));
    const secret = 'ghp_444444444444444444444444444444444444';

    try {
      await writeFile(path.join(root, 'package.json'), '{}');
      await mkdir(path.join(root, 'a'), { recursive: true });
      await writeFile(path.join(root, 'a-b.ts'), `const token = "${secret}";\n`);
      await writeFile(path.join(root, 'a', 'b.ts'), `const token = "${secret}";\n`);
      await writeFile(
        path.join(root, 'fixture.test.ts'),
        `// toolip:allow-secret-fixture\nconst token = "${secret}";\n`
      );

      const result = await runSecurityDoctor(root);
      const github = result.findings.filter(
        (finding) => finding.ruleId === 'TOOLIP-SECRET-GITHUB-TOKEN'
      );

      expect(github).toHaveLength(2);
      expect(new Set(github.map((finding) => finding.id)).size).toBe(2);
      expect(github.map((finding) => finding.location?.file).sort()).toEqual([
        'a-b.ts',
        'a/b.ts'
      ]);
      expect(
        github.some((finding) => finding.location?.file === 'fixture.test.ts')
      ).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
