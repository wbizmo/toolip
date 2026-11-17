#!/usr/bin/env node
/**
 * Local-only signed distribution-manifest constructor. This script does not
 * download toolchains, create binaries, upload release assets, create tags or
 * assert that any artifact passed runtime compatibility tests.
 *
 * The private signing key is supplied from a separately administered path.
 * A release remains unapproved until independent verification and owner signoff.
 */
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  lstatSync, openSync, readFileSync, readSync, readdirSync,
  closeSync, writeFileSync, unlinkSync
} from 'node:fs';
import path from 'node:path';

const versionRe = /^[0-9]+\.[0-9]+\.[0-9]+$/u;
const gitRe = /^[a-f0-9]{40}$/u;
const targetRe = /^(?:darwin-(?:arm64|x64)|linux-(?:arm64|x64)-(?:gnu|musl)|windows-(?:arm64|x64))$/u;
const maximumAssetBytes = 8 * 1024 * 1024 * 1024;
const maxAssets = 32;
const repo = path.resolve(import.meta.dirname, '..');

function mandatory(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Release manifest requires ${name}.`);
  return value;
}

const version = mandatory('TOOLIP_RELEASE_VERSION');
const sourceGitSha = mandatory('TOOLIP_RELEASE_GIT_SHA');
const assetsDir = mandatory('TOOLIP_DISTRIBUTION_ASSETS_DIR');
const outputDir = mandatory('TOOLIP_DISTRIBUTION_OUTPUT_DIR');
const keyPath = mandatory('TOOLIP_DISTRIBUTION_SIGNING_KEY');
if (!versionRe.test(version) || !gitRe.test(sourceGitSha))
  throw new Error('Release identity must use exact version and source commit.');
for (const candidate of [assetsDir, outputDir, keyPath])
  if (!path.isAbsolute(candidate))
    throw new Error('Artifact, output and signing-key paths must be absolute.');

const currentSha = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: repo, encoding: 'utf8', timeout: 5_000
}).trim();
if (currentSha !== sourceGitSha)
  throw new Error('Working revision differs from the requested source Git SHA.');
if (execFileSync('git', ['status', '--porcelain'], {
  cwd: repo, encoding: 'utf8', timeout: 5_000
}).trim())
  throw new Error('A signed candidate requires a clean repository checkout.');
const pkg = JSON.parse(readFileSync(path.join(repo, 'package.json'), 'utf8'));
if (pkg.version !== version)
  throw new Error('Package version differs from expected release version.');

const keyInfo = lstatSync(keyPath);
if (!keyInfo.isFile() || keyInfo.isSymbolicLink() || keyInfo.size > 16 * 1024)
  throw new Error('Signing key must be a bounded, regular non-symlink file.');
const privateKey = createPrivateKey(readFileSync(keyPath));
if (privateKey.asymmetricKeyType !== 'ed25519')
  throw new Error('Distribution signatures require an Ed25519 private key.');
const artifactDirectory = lstatSync(assetsDir);
if (!artifactDirectory.isDirectory() || artifactDirectory.isSymbolicLink())
  throw new Error('Artifact directory must be a real directory.');

const filenames = readdirSync(assetsDir).sort();
if (filenames.length === 0 || filenames.length > maxAssets)
  throw new Error('The artifact directory is empty or exceeds the file budget.');
const assets = [];
const targets = new Set();
for (const filename of filenames) {
  const match = filename.match(
    new RegExp(`^toolip-${version.replaceAll('.', '\\.')}-(darwin-(?:arm64|x64)|linux-(?:arm64|x64)-(?:gnu|musl)|windows-(?:arm64|x64))\\.(tar\\.gz|zip)$`, 'u')
  );
  if (!match || !targetRe.test(match[1] ?? '') ||
      (match[1]?.startsWith('windows-') ? match[2] !== 'zip' : match[2] !== 'tar.gz'))
    throw new Error('Distribution artifact filename violates the supported target contract.');
  const target = match[1];
  if (!target || targets.has(target))
    throw new Error('Duplicate distribution target.');
  targets.add(target);
  const source = path.join(assetsDir, filename);
  const before = lstatSync(source, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() ||
      before.size <= 0n || before.size > BigInt(maximumAssetBytes))
    throw new Error('Distribution artifact is not a bounded regular file.');
  const hash = createHash('sha256');
  const handle = openSync(source, 'r');
  try {
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let cursor = 0;
    while (cursor < Number(before.size)) {
      const count = Math.min(buffer.length, Number(before.size) - cursor);
      const read = readSync(handle, buffer, 0, count, cursor);
      if (read <= 0) throw new Error('Artifact truncated during manifest creation.');
      hash.update(buffer.subarray(0, read));
      cursor += read;
    }
  } finally {
    closeSync(handle);
  }
  const after = lstatSync(source, { bigint: true });
  if (after.isSymbolicLink() || before.dev !== after.dev ||
      before.ino !== after.ino || before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs)
    throw new Error('Artifact changed during manifest hashing.');
  assets.push({
    target,
    filename,
    sha256: hash.digest('hex'),
    size: Number(before.size)
  });
}
assets.sort((a, b) => a.target.localeCompare(b.target));
const manifest = {
  schema: 'toolip.dev/distribution/v1',
  repository: 'wbizmo/toolip',
  version,
  sourceGitSha,
  artifactKind: 'standalone-runtime-bundle',
  assets
};
const bytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8');
if (bytes.byteLength > 64 * 1024)
  throw new Error('Distribution manifest exceeds the byte budget.');
const signature = sign(null, bytes, privateKey).toString('base64') + '\n';
const existing = lstatSync(outputDir);
if (!existing.isDirectory() || existing.isSymbolicLink())
  throw new Error('Output directory must be a real pre-existing directory.');
const manifestFile = path.join(outputDir, 'release-manifest.json');
const signatureFile = path.join(outputDir, 'release-manifest.sig');
for (const target of [manifestFile, signatureFile]) {
  try {
    lstatSync(target);
    throw new Error('Distribution output already exists; refusing overwrite.');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}
let manifestCreated = false;
try {
  writeFileSync(manifestFile, bytes, { mode: 0o600, flag: 'wx' });
  manifestCreated = true;
  writeFileSync(signatureFile, signature, { mode: 0o600, flag: 'wx' });
} catch (error) {
  // Do not leave a deceptively unsigned manifest if signature publication
  // fails. Never touch a pre-existing signature or another release output.
  if (manifestCreated) unlinkSync(manifestFile);
  throw error;
}
console.log(JSON.stringify({
  manifestFile, signatureFile, sourceGitSha, version,
  artifactCount: assets.length,
  signed: true,
  verifiedRuntimeParity: false,
  releaseApproved: false,
  published: false
}, null, 2));
