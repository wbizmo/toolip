import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createProgram } from '../../src/cli/program.js';
import { signSbomAttestation } from '../../src/core/sbom/attestation.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

describe('signed SBOM trust-store verification command', () => {
  it('selects a project key from an external store and rejects a revoked key', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-sbom-trust-store-')
    );
    roots.push(root);
    const trustRoot = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-sbom-trust-policy-')
    );
    roots.push(trustRoot);
    const keyPair = generateKeyPairSync('ed25519');
    const privateKeyPem = keyPair.privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const publicKeyPem = keyPair.publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();
    const documentPath = path.join(root, 'sbom.json');
    const attestationPath = path.join(root, 'sbom.attestation.json');
    const trustStorePath = path.join(trustRoot, 'trust-store.json');
    const document = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      components: []
    };
    const attestation = signSbomAttestation(document, {
      privateKeyPem,
      keyId: 'release-key-v2',
      projectId: 'acme/payments',
      toolipVersion: '3.2.1',
      scannerArtifactSha256: 'a'.repeat(64)
    });
    const activeKey = { publicKeyPem, status: 'active' };
    await Promise.all([
      writeFile(documentPath, JSON.stringify(document), 'utf8'),
      writeFile(attestationPath, JSON.stringify(attestation), 'utf8'),
      writeFile(
        trustStorePath,
        JSON.stringify({
          version: 1,
          projectId: 'acme/payments',
          maxAgeDays: 90,
          keys: { 'release-key-v2': activeKey }
        }),
        'utf8'
      )
    ]);
    const stdout = vi
      .spyOn(process.stdout, 'write')
      .mockImplementation(() => true);
    const originalExitCode = process.exitCode;
    try {
      await createProgram().parseAsync([
        'node',
        'toolip',
        'sbom',
        'verify',
        documentPath,
        '--project-root',
        root,
        '--attestation',
        attestationPath,
        '--trust-store',
        trustStorePath,
        '--key-id',
        'release-key-v2'
      ]);
      expect(stdout).toHaveBeenCalledWith(
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
              ...activeKey,
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
          'sbom',
          'verify',
          documentPath,
          '--project-root',
          root,
          '--attestation',
          attestationPath,
          '--trust-store',
          trustStorePath,
          '--key-id',
          'release-key-v2'
        ])
      ).rejects.toThrow('was revoked at');
    } finally {
      process.exitCode = originalExitCode;
      stdout.mockRestore();
    }
  });
});
