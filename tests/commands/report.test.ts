import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, truncate, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createProgram } from '../../src/cli/program.js';
import { createReport } from '../../src/core/report.js';
import { signReportEvidence } from '../../src/core/report-signature.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

describe('signed report verification command', () => {
  it('rejects report files over the bounded input size before parsing', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-report-limit-'));
    roots.push(root);
    const keyPair = generateKeyPairSync('ed25519');
    const publicKeyPath = path.join(root, 'trusted.pub');
    const reportPath = path.join(root, 'oversized.json');
    await writeFile(
      publicKeyPath,
      keyPair.publicKey.export({ type: 'spki', format: 'pem' }),
      { mode: 0o600 }
    );
    await writeFile(reportPath, '{}');
    await truncate(reportPath, 8 * 1024 * 1024 + 1);

    await expect(
      createProgram().parseAsync([
        'node',
        'toolip',
        'report',
        'verify',
        reportPath,
        '--public-key',
        publicKeyPath,
        '--key-id',
        'trusted-key',
        '--project-id',
        'org/repository'
      ])
    ).rejects.toMatchObject({ code: 'REPORT_INPUT_INVALID' });
  });

  it('verifies trusted report evidence and rejects a different scanner digest', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-report-cli-'));
    roots.push(root);
    const keyPair = generateKeyPairSync('ed25519');
    const privateKeyPem = keyPair.privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const publicKeyPem = keyPair.publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();
    const publicKeyPath = path.join(root, 'trusted.pub');
    const reportPath = path.join(root, 'report.json');
    const scannerDigest = 'a'.repeat(64);
    const sourceTreeDigest = 'c'.repeat(64);
    const report = signReportEvidence(
      createReport({
        version: '3.2.1-rc',
        command: 'scan',
        root: '/captured/project',
        findings: [],
        analysis: { state: 'complete', reasons: [] }
      }),
      {
        privateKeyPem,
        keyId: 'trusted-key',
        projectId: 'org/repository',
        scannerArtifactSha256: scannerDigest,
        issuedAt: new Date().toISOString(),
        subject: { sourceTreeDigest }
      }
    );
    await writeFile(publicKeyPath, publicKeyPem, { mode: 0o600 });
    await writeFile(reportPath, `${JSON.stringify(report)}\n`);
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const originalExitCode = process.exitCode;

    try {
      await createProgram().parseAsync([
        'node',
        'toolip',
        'report',
        'verify',
        reportPath,
        '--public-key',
        publicKeyPath,
        '--key-id',
        'trusted-key',
        '--project-id',
        'org/repository',
        '--scanner-artifact-sha256',
        scannerDigest,
        '--source-tree-sha256',
        sourceTreeDigest
      ]);
      expect(log).toHaveBeenLastCalledWith(
        expect.stringContaining('"status": "verified"')
      );
      expect(process.exitCode).toBe(originalExitCode);

      await createProgram().parseAsync([
        'node',
        'toolip',
        'report',
        'verify',
        reportPath,
        '--public-key',
        publicKeyPath,
        '--key-id',
        'trusted-key',
        '--project-id',
        'org/repository',
        '--scanner-artifact-sha256',
        'b'.repeat(64)
      ]);
      expect(log).toHaveBeenLastCalledWith(
        expect.stringContaining('"reason": "scanner-artifact-mismatch"')
      );
      expect(process.exitCode).toBe(2);

      await createProgram().parseAsync([
        'node',
        'toolip',
        'report',
        'verify',
        reportPath,
        '--public-key',
        publicKeyPath,
        '--key-id',
        'trusted-key',
        '--project-id',
        'org/repository',
        '--source-tree-sha256',
        'f'.repeat(64)
      ]);
      expect(log).toHaveBeenLastCalledWith(
        expect.stringContaining('"reason": "source-tree-mismatch"')
      );
      expect(process.exitCode).toBe(2);
    } finally {
      process.exitCode = originalExitCode;
      log.mockRestore();
    }
  });

  it('uses an external trust store for project identity and key revocation', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-report-trust-store-')
    );
    roots.push(root);
    const trustRoot = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-report-trust-policy-')
    );
    roots.push(trustRoot);
    const keyPair = generateKeyPairSync('ed25519');
    const privateKeyPem = keyPair.privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const publicKeyPem = keyPair.publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();
    const reportPath = path.join(root, 'report.json');
    const trustStorePath = path.join(trustRoot, 'trust-store.json');
    const report = signReportEvidence(
      createReport({
        version: '3.2.1-rc',
        command: 'scan',
        root: '/captured/project',
        findings: [],
        analysis: { state: 'complete', reasons: [] }
      }),
      {
        privateKeyPem,
        keyId: 'release-key-v2',
        projectId: 'acme/payments',
        scannerArtifactSha256: 'a'.repeat(64),
        issuedAt: new Date().toISOString(),
        subject: { sourceTreeDigest: 'c'.repeat(64) }
      }
    );
    await writeFile(reportPath, `${JSON.stringify(report)}\n`);
    const keyPolicy = {
      publicKeyPem,
      status: 'active'
    };
    await writeFile(
      trustStorePath,
      JSON.stringify({
        version: 1,
        projectId: 'acme/payments',
        maxAgeDays: 90,
        keys: { 'release-key-v2': keyPolicy }
      }),
      'utf8'
    );
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const originalExitCode = process.exitCode;
    try {
      await createProgram().parseAsync([
        'node',
        'toolip',
        'report',
        'verify',
        reportPath,
        '--project-root',
        root,
        '--trust-store',
        trustStorePath,
        '--key-id',
        'release-key-v2'
      ]);
      expect(log).toHaveBeenLastCalledWith(
        expect.stringContaining('"status": "verified"')
      );

      await writeFile(
        trustStorePath,
        JSON.stringify({
          version: 1,
          projectId: 'acme/payments',
          maxAgeDays: 90,
          keys: {
            'release-key-v2': {
              ...keyPolicy,
              status: 'revoked',
              revokedAt: new Date().toISOString()
            }
          }
        }),
        'utf8'
      );
      await expect(
        createProgram().parseAsync([
          'node',
          'toolip',
          'report',
          'verify',
          reportPath,
          '--project-root',
          root,
          '--trust-store',
          trustStorePath,
          '--key-id',
          'release-key-v2'
        ])
      ).rejects.toThrow('was revoked at');
    } finally {
      process.exitCode = originalExitCode;
      log.mockRestore();
    }
  });
});
