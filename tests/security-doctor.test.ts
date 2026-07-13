import {
  mkdtemp,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { runSecurityDoctor } from '../src/core/security-doctor.js';

describe('runSecurityDoctor', () => {
  it('detects secrets, dangerous code, weak JWT config, and open CORS', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-doctor-')
    );

    try {
      await writeFile(path.join(root, 'package.json'), '{}');

      await writeFile(
        path.join(root, 'server.ts'),
        `
import { exec } from 'node:child_process';

const githubToken = "ghp_123456789012345678901234567890123456";
const password = "strong-password";
const jwtSecret = "secret";
const cors = { origin: "*" };

eval(source);
const generated = new Function("value", source);
exec(userInput);
`
      );

      const result = await runSecurityDoctor(root);
      const ids = result.findings.map((finding) => finding.id);

      expect(result.summary.secrets).toBeGreaterThanOrEqual(2);
      expect(result.summary.dangerousCode).toBeGreaterThanOrEqual(3);
      expect(result.summary.configuration).toBeGreaterThanOrEqual(2);
      expect(
        ids.some((id) =>
          id.includes('TOOLIP-SECRET-GITHUB-TOKEN')
        )
      ).toBe(true);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('respects .toolipignore while scanning', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-doctor-ignore-')
    );

    try {
      await writeFile(path.join(root, 'package.json'), '{}');
      await writeFile(
        path.join(root, '.toolipignore'),
        'ignored.ts\n'
      );
      await writeFile(
        path.join(root, 'ignored.ts'),
        'eval(source);'
      );

      const result = await runSecurityDoctor(root);

      expect(
        result.findings.some(
          (finding) => finding.file === 'ignored.ts'
        )
      ).toBe(false);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });
});
