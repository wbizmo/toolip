import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runSecurityDoctor } from '../src/core/security-doctor.js';

describe('runSecurityDoctor', () => {
  it('detects secrets, dangerous code, weak JWT config, and open CORS', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-doctor-'));

    try {
      await mkdir(path.join(root, 'src'), { recursive: true });

      await writeFile(
        path.join(root, 'src', 'index.ts'),
        `
const token = "ghp_1234567890abcdefghijklmnopqrstuv";
const password = "supersecretpassword";
const jwtSecret = "secret";
eval("console.log(1)");
new Function("return 1");
exec("rm -rf " + userInput);
const cors = { origin: "*" };
const jwt = { expiresIn: "365d" };
`
      );

      await writeFile(path.join(root, 'package.json'), JSON.stringify({}));

      const result = await runSecurityDoctor(root);
      const ids = result.findings.map((finding) => finding.id);

      expect(result.summary.secrets).toBeGreaterThanOrEqual(2);
      expect(result.summary.dangerousCode).toBeGreaterThanOrEqual(3);
      expect(result.summary.configuration).toBeGreaterThanOrEqual(2);
      expect(ids.some((id) => id.includes('TOOLIP-SECRET-GITHUB-TOKEN'))).toBe(true);
      expect(ids.some((id) => id.includes('TOOLIP-DANGEROUS-EVAL'))).toBe(true);
      expect(ids.some((id) => id.includes('TOOLIP-CONFIG-OPEN-CORS'))).toBe(true);
      expect(ids.some((id) => id.includes('TOOLIP-CONFIG-WEAK-JWT-SECRET'))).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('respects .toolipignore while scanning', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-doctor-ignore-'));

    try {
      await mkdir(path.join(root, 'ignored'), { recursive: true });
      await writeFile(path.join(root, '.toolipignore'), 'ignored\n');
      await writeFile(path.join(root, 'package.json'), JSON.stringify({}));
      await writeFile(path.join(root, 'ignored', 'secret.ts'), 'const password = "supersecretpassword";');

      const result = await runSecurityDoctor(root);

      expect(result.findings.some((finding) => finding.file?.includes('ignored'))).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
