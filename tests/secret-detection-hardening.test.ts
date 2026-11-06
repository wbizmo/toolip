import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  runSecurityDoctor,
  shouldScanSecrets
} from '../src/core/security-doctor.js';

describe('secret detection hardening', () => {
  it('excludes common font assets before text reads', () => {
    for (const font of [
      'font.eot',
      'font.otf',
      'font.ttf',
      'font.woff',
      'font.woff2'
    ]) {
      expect(shouldScanSecrets(font, path.extname(font).slice(1))).toBe(false);
    }
  });

  it('reports every same-rule occurrence with unique locations and no secret fragments', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-secret-occurrences-')
    );
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
        expect(summary).toBe('[redacted secret]');
        expect(summary).not.toContain('ghp_');
        expect(summary).not.toContain('abcdefgh');
        expect(finding.evidence?.[0]?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not lower a real credential merely because it is in a test file', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-secret-test-severity-')
    );

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

  it('ignores source fixture markers and accepts only trusted caller policy', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-secret-identities-')
    );
    const secret = 'ghp_444444444444444444444444444444444444';

    try {
      await writeFile(path.join(root, 'package.json'), '{}');
      await mkdir(path.join(root, 'a'), { recursive: true });
      await writeFile(
        path.join(root, 'a-b.ts'),
        `const token = "${secret}";\n`
      );
      await writeFile(
        path.join(root, 'a', 'b.ts'),
        `const token = "${secret}";\n`
      );
      await writeFile(
        path.join(root, 'fixture.test.ts'),
        `// toolip:allow-secret-fixture\nconst token = "${secret}";\n`
      );

      const result = await runSecurityDoctor(root);
      const github = result.findings.filter(
        (finding) => finding.ruleId === 'TOOLIP-SECRET-GITHUB-TOKEN'
      );

      expect(github).toHaveLength(3);
      expect(
        github.some((finding) => finding.location?.file === 'fixture.test.ts')
      ).toBe(true);
      const trusted = await runSecurityDoctor(root, {
        trustedFixtureSuppressions: [
          {
            id: 'fixture-gh-token-001',
            ruleId: 'TOOLIP-SECRET-GITHUB-TOKEN',
            filePath: 'fixture.test.ts',
            owner: 'security-tests',
            justification: 'Synthetic test-only credential',
            expiresAt: '2999-01-01T00:00:00.000Z'
          }
        ]
      });
      expect(trusted.suppressedFixtures).toEqual({
        count: 1,
        ids: ['fixture-gh-token-001']
      });
      expect(
        trusted.findings.some(
          (finding) => finding.location?.file === 'fixture.test.ts'
        )
      ).toBe(false);
      const rejectedPolicy = await runSecurityDoctor(root, {
        trustedFixtureSuppressions: [
          {
            id: 'expired',
            ruleId: 'TOOLIP-SECRET-GITHUB-TOKEN',
            filePath: 'fixture.test.ts',
            owner: 'security-tests',
            justification: 'Expired synthetic fixture policy',
            expiresAt: '2000-01-01T00:00:00.000Z'
          },
          {
            id: 'unknown-scope',
            ruleId: 'TOOLIP-SECRET-GITHUB-TOKEN',
            filePath: 'elsewhere.test.ts',
            owner: 'security-tests',
            justification: 'Wrong path'
          }
        ]
      });
      expect(rejectedPolicy.suppressedFixtures.count).toBe(0);
      expect(
        rejectedPolicy.findings.some(
          (finding) => finding.location?.file === 'fixture.test.ts'
        )
      ).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('scans npmrc and readable extensionless/nested configuration files', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-secret-config-'));
    const token = `npm_${'a'.repeat(32)}`;
    try {
      await mkdir(path.join(root, 'nested'), { recursive: true });
      await writeFile(
        path.join(root, '.npmrc'),
        `//registry.npmjs.org/:_authToken=${token}\n`
      );
      await writeFile(
        path.join(root, 'nested', 'deploy.conf'),
        'password = "unique-password-value"\n'
      );
      const result = await runSecurityDoctor(root);
      expect(
        result.findings.some(
          (finding) => finding.ruleId === 'TOOLIP-SECRET-NPM-AUTH'
        )
      ).toBe(true);
      expect(
        result.findings.some(
          (finding) => finding.location?.file === 'nested/deploy.conf'
        )
      ).toBe(true);
      expect(JSON.stringify(result)).not.toContain(token);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('retains quoted passphrase detection without treating URL queries as userinfo', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-secret-passphrase-')
    );
    try {
      await writeFile(
        path.join(root, 'credentials.conf'),
        'password = "correct horse battery staple"\n' +
          'callback = "https://example.com?next:user@other.example"\n'
      );
      const result = await runSecurityDoctor(root);
      expect(
        result.findings.some(
          (finding) => finding.ruleId === 'TOOLIP-SECRET-HARDCODED-PASSWORD'
        )
      ).toBe(true);
      expect(
        result.findings.some(
          (finding) => finding.ruleId === 'TOOLIP-SECRET-URL-CREDENTIALS'
        )
      ).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not report environment references as literal credentials', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-secret-refs-'));
    try {
      await writeFile(
        path.join(root, '.npmrc'),
        '//registry.npmjs.org/:_authToken=$' + '{NPM_TOKEN}\n'
      );
      await writeFile(
        path.join(root, 'settings.conf'),
        'password = process.env.DB_PASSWORD\n' +
          'passwd = $' +
          '{DB_PASSWORD}\n' +
          'pwd = getPassword(cfg)\n' +
          'database = https://deploy:$' +
          '{DB_PASSWORD}@db.example.test\n' +
          'databaseAlias = https://deploy:$DB_PASSWORD@db.example.test\n' +
          'databaseEnv = https://deploy:env.DB_PASSWORD@db.example.test\n'
      );
      await writeFile(
        path.join(root, 'settings.ts'),
        'const config = { password: DB_PASSWORD };\n' +
          'const explicit = { password: "quoted-test-password-value" };\n'
      );
      const result = await runSecurityDoctor(root);
      expect(
        result.findings.some(
          (finding) =>
            finding.ruleId === 'TOOLIP-SECRET-NPM-AUTH' ||
            finding.ruleId === 'TOOLIP-SECRET-HARDCODED-PASSWORD' ||
            finding.ruleId === 'TOOLIP-SECRET-URL-CREDENTIALS'
        )
      ).toBe(true);
      expect(
        result.findings
          .filter(
            (finding) =>
              finding.ruleId === 'TOOLIP-SECRET-HARDCODED-PASSWORD' ||
              finding.ruleId === 'TOOLIP-SECRET-URL-CREDENTIALS'
          )
          .map((finding) => finding.location?.file)
      ).toEqual(['settings.ts']);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
