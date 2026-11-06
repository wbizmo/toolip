import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { createScannerContext } from '../src/core/scanner-context.js';
import { runSecurityDoctor } from '../src/core/security-doctor.js';

describe('runSecurityDoctor', () => {
  it('detects secrets, dangerous code, weak JWT config, and open CORS', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-doctor-'));

    try {
      await writeFile(path.join(root, 'package.json'), '{}');

      const githubToken = `ghp_${'1'.repeat(36)}`;
      await writeFile(
        path.join(root, 'server.ts'),
        `
import { exec } from 'node:child_process';

const githubToken = "${githubToken}";
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
      expect(ids.some((id) => id.includes('TOOLIP-SECRET-GITHUB-TOKEN'))).toBe(
        true
      );
      expect(result.findings.every((finding) => Boolean(finding.ruleId))).toBe(
        true
      );
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('respects .toolipignore while scanning', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-doctor-ignore-'));

    try {
      await writeFile(path.join(root, 'package.json'), '{}');
      await writeFile(path.join(root, '.toolipignore'), 'ignored.ts\n');
      await writeFile(path.join(root, 'ignored.ts'), 'eval(source);');

      const result = await runSecurityDoctor(root);

      expect(
        result.findings.some(
          (finding) => finding.location?.file === 'ignored.ts'
        )
      ).toBe(false);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('skips files changed after discovery when scanning a ScannerContext', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-doctor-snapshot-')
    );

    try {
      const source = path.join(root, 'app.ts');
      await writeFile(source, 'const safe = true;');
      const context = await createScannerContext(root);
      await writeFile(
        source,
        'const changedAfterDiscovery = true; eval(input);'
      );

      const result = await runSecurityDoctor(context);

      expect(result.summary.filesSkipped).toBe(1);
      expect(result.coverage.state).toBe('failed');
      expect(
        result.findings.some((finding) => finding.location?.file === 'app.ts')
      ).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('binds finding metadata to the discovered and read source snapshot', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-doctor-provenance-')
    );
    const content = 'eval(input);';

    try {
      await writeFile(path.join(root, 'app.ts'), content);
      const context = await createScannerContext(root);
      const discovered = context.files.find(
        (file) => file.relativePath === 'app.ts'
      );
      const result = await runSecurityDoctor(context);
      const finding = result.findings.find(
        (item) => item.location?.file === 'app.ts'
      );

      expect(discovered?.snapshot).toBeDefined();
      expect(finding).toBeDefined();
      expect(finding?.metadata?.sourceProvenance).toMatchObject({
        path: 'app.ts',
        sha256: createHash('sha256').update(content).digest('hex'),
        bytes: Buffer.byteLength(content),
        discoverySnapshot: {
          dev: discovered?.snapshot?.dev.toString(),
          ino: discovered?.snapshot?.ino.toString(),
          size: Buffer.byteLength(content)
        },
        readSnapshot: {
          dev: discovered?.snapshot?.dev.toString(),
          ino: discovered?.snapshot?.ino.toString(),
          size: Buffer.byteLength(content)
        }
      });
      expect(() => JSON.stringify(finding)).not.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
