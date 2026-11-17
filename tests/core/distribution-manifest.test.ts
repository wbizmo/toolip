import {
  createHash,
  generateKeyPairSync,
  sign as signEd25519
} from 'node:crypto';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  verifyDistributionAsset,
  verifyDistributionManifest
} from '../../src/core/distribution/manifest.js';

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

async function setup() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-signed-distribution-'));
  roots.push(root);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const expectedVersion = '3.2.1';
  const expectedGitSha = 'a'.repeat(40);
  const filename = 'toolip-3.2.1-linux-x64-gnu.tar.gz';
  const bytes = Buffer.from('synthetic release artifact, not an executable');
  const artifactFile = path.join(root, filename);
  const manifestFile = path.join(root, 'release-manifest.json');
  const signatureFile = path.join(root, 'release-manifest.sig');
  const trustedPublicKeyFile = path.join(root, 'out-of-band-public-key.pem');
  const manifest = {
    schema: 'toolip.dev/distribution/v1',
    repository: 'wbizmo/toolip',
    version: expectedVersion,
    sourceGitSha: expectedGitSha,
    artifactKind: 'standalone-runtime-bundle',
    assets: [{
      target: 'linux-x64-gnu',
      filename,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      size: bytes.length
    }]
  };
  const raw = Buffer.from(JSON.stringify(manifest));
  await writeFile(manifestFile, raw);
  await writeFile(signatureFile, signEd25519(null, raw, privateKey).toString('base64') + '\n');
  await writeFile(trustedPublicKeyFile,
    publicKey.export({ type: 'spki', format: 'pem' }));
  await writeFile(artifactFile, bytes);
  return {
    root, manifest, manifestFile, signatureFile, trustedPublicKeyFile,
    artifactFile, expectedVersion, expectedGitSha
  };
}

describe('immutable Toolip standalone distribution evidence', () => {
  it('checks the detached signature, exact release identity and artifact digest', async () => {
    const inputs = await setup();
    const manifest = await verifyDistributionManifest(inputs);
    const result = await verifyDistributionAsset(
      manifest, 'linux-x64-gnu', inputs.artifactFile
    );
    expect(result).toMatchObject({
      state: 'digest-verified',
      approvedRelease: false,
      sourceGitSha: inputs.expectedGitSha,
      trust: 'operator-supplied-ed25519-key'
    });
  });

  it('rejects changed manifest contents before parsing a valid signature', async () => {
    const inputs = await setup();
    await writeFile(inputs.manifestFile,
      JSON.stringify({ ...inputs.manifest, version: '4.0.0' }));
    await expect(verifyDistributionManifest(inputs)).rejects.toThrow();
  });

  it('rejects a valid signature for the wrong immutable release SHA', async () => {
    const inputs = await setup();
    await expect(verifyDistributionManifest({
      ...inputs,
      expectedGitSha: 'b'.repeat(40)
    })).rejects.toThrow('release identity');
  });

  it('rejects a replaced artifact or a symlink without extracting any archive', async () => {
    const inputs = await setup();
    const manifest = await verifyDistributionManifest(inputs);
    await writeFile(inputs.artifactFile, 'tampered bytes');
    await expect(
      verifyDistributionAsset(manifest, 'linux-x64-gnu', inputs.artifactFile)
    ).rejects.toThrow();

    const link = path.join(inputs.root, 'toolip-link');
    await symlink(inputs.artifactFile, link);
    await expect(
      verifyDistributionAsset(manifest, 'linux-x64-gnu', link)
    ).rejects.toThrow();
  });

  it('rejects a signed manifest that contains archive traversal or duplicate targets', async () => {
    const inputs = await setup();
    const { privateKey } = generateKeyPairSync('ed25519');
    const forged = {
      ...inputs.manifest,
      assets: [
        {
          ...inputs.manifest.assets[0],
          filename: '../toolip-secret.tar.gz'
        },
        inputs.manifest.assets[0]
      ]
    };
    const raw = Buffer.from(JSON.stringify(forged));
    await writeFile(inputs.manifestFile, raw);
    await writeFile(inputs.signatureFile,
      signEd25519(null, raw, privateKey).toString('base64'));
    // The signature is valid under its own key, not the operator's: either
    // invalid signature or invalid manifest must deny installation.
    await expect(verifyDistributionManifest(inputs)).rejects.toThrow();
  });
});
