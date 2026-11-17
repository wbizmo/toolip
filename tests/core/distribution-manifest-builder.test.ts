import {
  createHash, generateKeyPairSync
} from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  mkdtemp, mkdir, readFile, rm, writeFile
} from 'node:fs/promises';
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

describe('unsigned candidate to signed distribution manifest', () => {
  it('binds local archive bytes, source commit and operator key without publishing anything', async () => {
    const root = path.resolve(import.meta.dirname, '../..');
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: root, encoding: 'utf8'
    }).trim();
    const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'toolip-manifest-sign-'));
    roots.push(workspace);
    const artifacts = path.join(workspace, 'artifacts');
    const output = path.join(workspace, 'signed');
    await mkdir(artifacts);
    await mkdir(output);
    const target = 'darwin-x64';
    const filename = `toolip-${pkg.version}-${target}.tar.gz`;
    const archive = Buffer.from('synthetic signed candidate fixture; not an executable');
    await writeFile(path.join(artifacts, filename), archive);
    const keys = generateKeyPairSync('ed25519');
    const privateKey = path.join(workspace, 'private.pem');
    const publicKey = path.join(workspace, 'public.pem');
    await writeFile(privateKey, keys.privateKey.export({
      type: 'pkcs8', format: 'pem'
    }));
    await writeFile(publicKey, keys.publicKey.export({
      type: 'spki', format: 'pem'
    }));
    const result = spawnSync(process.execPath, [
      path.join(root, 'scripts/create-distribution-manifest.mjs')
    ], {
      cwd: root,
      encoding: 'utf8',
      shell: false,
      env: {
        ...process.env,
        TOOLIP_RELEASE_VERSION: pkg.version,
        TOOLIP_RELEASE_GIT_SHA: commit,
        TOOLIP_DISTRIBUTION_ASSETS_DIR: artifacts,
        TOOLIP_DISTRIBUTION_OUTPUT_DIR: output,
        TOOLIP_DISTRIBUTION_SIGNING_KEY: privateKey
      }
    });
    expect(result.status).toBe(0);
    const meta = JSON.parse(result.stdout);
    expect(meta.signed).toBe(true);
    expect(meta.releaseApproved).toBe(false);
    expect(meta.published).toBe(false);
    const manifest = await verifyDistributionManifest({
      manifestFile: path.join(output, 'release-manifest.json'),
      signatureFile: path.join(output, 'release-manifest.sig'),
      trustedPublicKeyFile: publicKey,
      expectedVersion: pkg.version,
      expectedGitSha: commit
    });
    expect(manifest.assets[0]?.sha256).toBe(
      createHash('sha256').update(archive).digest('hex')
    );
    const verified = await verifyDistributionAsset(
      manifest, target, path.join(artifacts, filename)
    );
    expect(verified.approvedRelease).toBe(false);
  }, 30_000);
});
