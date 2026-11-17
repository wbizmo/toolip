import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import { readBoundedRegularFile } from '../bounded-file.js';

const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_SIGNATURE_BYTES = 256;
const MAX_ASSETS = 32;
const MAX_ARTIFACT_BYTES = 8n * 1024n * 1024n * 1024n;
const digestPattern = /^[a-f0-9]{64}$/u;
const gitPattern = /^[a-f0-9]{40}$/u;
const versionPattern = /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/u;
const targetPattern = /^(?:linux|darwin|windows)-(?:x64|arm64)(?:-(?:gnu|musl))?$/u;
const filenamePattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,160}$/u;

export type DistributionAsset = Readonly<{
  target: string;
  filename: string;
  sha256: string;
  size: number;
}>;

export type DistributionManifest = Readonly<{
  schema: 'toolip.dev/distribution/v1';
  repository: 'wbizmo/toolip';
  version: string;
  sourceGitSha: string;
  artifactKind: 'standalone-runtime-bundle';
  assets: readonly DistributionAsset[];
}>;

export type VerifiedAsset = Readonly<{
  state: 'digest-verified';
  version: string;
  sourceGitSha: string;
  target: string;
  filename: string;
  sha256: string;
  size: number;
  trust: 'operator-supplied-ed25519-key';
  /** Signature authenticity does not establish official release approval. */
  approvedRelease: false;
}>;

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
    ? value as Record<string, unknown> : undefined;
}

function fieldsExactly(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).length === allowed.length &&
    Object.keys(value).every((key) => allowed.includes(key));
}

function parseManifest(value: unknown): DistributionManifest {
  const manifest = record(value);
  if (!manifest ||
      !fieldsExactly(manifest, [
        'schema', 'repository', 'version', 'sourceGitSha',
        'artifactKind', 'assets'
      ]) ||
      manifest.schema !== 'toolip.dev/distribution/v1' ||
      manifest.repository !== 'wbizmo/toolip' ||
      manifest.artifactKind !== 'standalone-runtime-bundle' ||
      typeof manifest.version !== 'string' ||
      !versionPattern.test(manifest.version) ||
      typeof manifest.sourceGitSha !== 'string' ||
      !gitPattern.test(manifest.sourceGitSha) ||
      !Array.isArray(manifest.assets) ||
      manifest.assets.length === 0 ||
      manifest.assets.length > MAX_ASSETS
  ) throw new TypeError('Distribution manifest has an unsupported schema or identity.');

  const assets: DistributionAsset[] = [];
  const targets = new Set<string>();
  const filenames = new Set<string>();
  for (const value of manifest.assets) {
    const asset = record(value);
    if (!asset ||
        !fieldsExactly(asset, ['target', 'filename', 'sha256', 'size']) ||
        typeof asset.target !== 'string' ||
        !targetPattern.test(asset.target) ||
        typeof asset.filename !== 'string' ||
        !filenamePattern.test(asset.filename) ||
        typeof asset.sha256 !== 'string' ||
        !digestPattern.test(asset.sha256) ||
        !Number.isSafeInteger(asset.size) ||
        (asset.size as number) <= 0 ||
        BigInt(asset.size as number) > MAX_ARTIFACT_BYTES ||
        targets.has(asset.target) ||
        filenames.has(asset.filename)
    ) throw new TypeError('Distribution manifest asset is invalid or duplicated.');
    targets.add(asset.target);
    filenames.add(asset.filename);
    assets.push(Object.freeze({
      target: asset.target,
      filename: asset.filename,
      sha256: asset.sha256,
      size: asset.size as number
    }));
  }
  return Object.freeze({
    schema: 'toolip.dev/distribution/v1',
    repository: 'wbizmo/toolip',
    version: manifest.version,
    sourceGitSha: manifest.sourceGitSha,
    artifactKind: 'standalone-runtime-bundle',
    assets: Object.freeze(assets)
  });
}

/**
 * Verify detached Ed25519 signature over the *exact UTF-8 manifest bytes*,
 * not over reserialized JSON. The key must be supplied by the operator from a
 * separately trusted channel, never downloaded alongside the manifest.
 */
export async function verifyDistributionManifest(input: {
  manifestFile: string;
  signatureFile: string;
  trustedPublicKeyFile: string;
  expectedVersion: string;
  expectedGitSha: string;
}): Promise<DistributionManifest> {
  if (!versionPattern.test(input.expectedVersion) ||
      !gitPattern.test(input.expectedGitSha))
    throw new TypeError('Expected immutable release identity is invalid.');
  const [bytes, signatureBytes, publicKeyBytes] = await Promise.all([
    readBoundedRegularFile(input.manifestFile, MAX_MANIFEST_BYTES),
    readBoundedRegularFile(input.signatureFile, MAX_SIGNATURE_BYTES),
    readBoundedRegularFile(input.trustedPublicKeyFile, 16 * 1024)
  ]);
  const rawSignature = new TextDecoder('utf-8', { fatal: true })
    .decode(signatureBytes).trim();
  if (!/^[A-Za-z0-9+/]{86}==$/u.test(rawSignature))
    throw new Error('Detached manifest signature is invalid.');
  const publicKeyText = new TextDecoder('utf-8', { fatal: true })
    .decode(publicKeyBytes);
  const publicKey = createPublicKey(publicKeyText);
  if (publicKey.type !== 'public' ||
      publicKey.asymmetricKeyType !== 'ed25519')
    throw new Error('Distribution trust anchor must be an Ed25519 public key.');
  if (!verifySignature(null, bytes, publicKey, Buffer.from(rawSignature, 'base64')))
    throw new Error('Distribution manifest signature is not trusted.');
  const manifest = parseManifest(JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  ) as unknown);
  if (manifest.version !== input.expectedVersion ||
      manifest.sourceGitSha !== input.expectedGitSha)
    throw new Error('Distribution manifest release identity does not match expected version and revision.');
  return manifest;
}

/**
 * Hash a bounded artifact through the same open file descriptor. Never trust
 * a filename alone and never unpack an archive in this verifier.
 */
export async function verifyDistributionAsset(
  manifest: DistributionManifest,
  target: string,
  artifactFile: string
): Promise<VerifiedAsset> {
  const expected = manifest.assets.find((entry) => entry.target === target);
  if (!expected || path.basename(artifactFile) !== expected.filename)
    throw new Error('Requested asset target or filename is not in the signed manifest.');
  const before = await lstat(artifactFile, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() ||
      before.size !== BigInt(expected.size) ||
      before.size > MAX_ARTIFACT_BYTES)
    throw new Error('Distribution artifact is not an expected regular file.');
  const handle = await open(
    artifactFile,
    constants.O_RDONLY |
      (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
  );
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev ||
        opened.ino !== before.ino || opened.size !== before.size ||
        opened.mtimeNs !== before.mtimeNs || opened.ctimeNs !== before.ctimeNs)
      throw new Error('Distribution artifact was replaced before hashing.');
    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (position < expected.size) {
      const { bytesRead } = await handle.read(
        buffer, 0, Math.min(buffer.length, expected.size - position), position
      );
      if (bytesRead === 0)
        throw new Error('Distribution artifact ended before declared size.');
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const namedAfter = await lstat(artifactFile, { bigint: true });
    if (after.dev !== opened.dev || after.ino !== opened.ino ||
        after.size !== opened.size || after.mtimeNs !== opened.mtimeNs ||
        after.ctimeNs !== opened.ctimeNs ||
        namedAfter.isSymbolicLink() || namedAfter.dev !== opened.dev ||
        namedAfter.ino !== opened.ino || namedAfter.size !== opened.size ||
        namedAfter.mtimeNs !== opened.mtimeNs ||
        namedAfter.ctimeNs !== opened.ctimeNs)
      throw new Error('Distribution artifact was modified during hashing.');
    if (digest.digest('hex') !== expected.sha256)
      throw new Error('Distribution artifact checksum does not match the signed manifest.');
    return Object.freeze({
      state: 'digest-verified',
      version: manifest.version,
      sourceGitSha: manifest.sourceGitSha,
      target,
      filename: expected.filename,
      sha256: expected.sha256,
      size: expected.size,
      trust: 'operator-supplied-ed25519-key',
      approvedRelease: false
    });
  } finally {
    await handle.close();
  }
}
