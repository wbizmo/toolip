import {
  mkdtemp,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { runSecurityDoctor } from '../../src/core/security-doctor.js';

describe('doctor RegExp.exec regression', () => {
  it('does not report regex parsing as shell execution', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-doctor-regexp-')
    );

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          name: 'fixture',
          version: '1.0.0'
        })
      );

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
            finding.category === 'dangerous-code'
        )
      ).toBe(false);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('does report resolved shell execution', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-doctor-shell-')
    );

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          name: 'fixture',
          version: '1.0.0'
        })
      );

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
            finding.category === 'dangerous-code' &&
            finding.title.includes('child_process.exec')
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
