import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runSecurityDoctor } from '../src/core/security-doctor.js';

describe('security doctor hardening', () => {
  it('detects npm tokens', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-npm-token-'));

    try {
      await writeFile(path.join(root, 'package.json'), '{}');

      await writeFile(
        path.join(root, 'index.ts'),
        'const token = "npm_123456789012345678901234567890";'
      );

      const result = await runSecurityDoctor(root);

      expect(
        result.findings.some((finding) =>
          finding.id.includes('TOOLIP-SECRET-NPM-TOKEN')
        )
      ).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not create findings for clean code', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-clean-project-'));

    try {
      await writeFile(path.join(root, 'package.json'), '{}');

      await writeFile(
        path.join(root, 'index.ts'),
        `
export function sum(a: number, b: number) {
  return a + b;
}
`
      );

      const result = await runSecurityDoctor(root);

      const criticalOrHigh = result.findings.filter(
        (finding) =>
          finding.severity === 'critical' ||
          finding.severity === 'high'
      );

      expect(criticalOrHigh.length).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
