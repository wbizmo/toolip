import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { runSecurityDoctor } from '../src/core/security-doctor.js';

describe('security detection accuracy', () => {
  it('does not mistake RegExp.exec() for child_process.exec()', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-regexp-exec-')
    );

    try {
      await writeFile(path.join(root, 'package.json'), '{}');

      await writeFile(
        path.join(root, 'auth.service.ts'),
        `
export function parseDuration(value: string) {
  return /^(\\d+)([smhd])$/.exec(value);
}
`
      );

      const result = await runSecurityDoctor(root);

      expect(
        result.findings.some(
          (finding) =>
            finding.id.includes(
              'TOOLIP-DANGEROUS-CHILD-PROCESS-EXEC'
            )
        )
      ).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('still detects genuine direct exec usage', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-shell-exec-')
    );

    try {
      await writeFile(path.join(root, 'package.json'), '{}');

      await writeFile(
        path.join(root, 'runner.ts'),
        `
import { exec } from 'node:child_process';

exec(userInput);
`
      );

      const result = await runSecurityDoctor(root);

      expect(
        result.findings.some(
          (finding) =>
            finding.id.includes(
              'TOOLIP-DANGEROUS-CHILD-PROCESS-EXEC'
            )
        )
      ).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('downgrades password-like values inside test fixtures', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-test-fixture-')
    );

    try {
      await mkdir(path.join(root, 'tests'), {
        recursive: true
      });

      await writeFile(path.join(root, 'package.json'), '{}');

      await writeFile(
        path.join(root, 'tests', 'validation.test.ts'),
        `
const user = {
  password: "strong-password"
};
`
      );

      const result = await runSecurityDoctor(root);

      const finding = result.findings.find(
        (item) =>
          item.id.includes(
            'TOOLIP-SECRET-HARDCODED-PASSWORD'
          )
      );

      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('low');
      expect(finding?.title).toContain('Potential test fixture');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
