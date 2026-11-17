#!/usr/bin/env node
/*
 * Build a LOCAL, UNSIGNED multi-platform OCI image candidate for review.
 * No registry push, version tag, release, trust claim, provenance claim, or
 * privileged Docker socket mount is automatically added to the resulting image.
 * Container build itself may access pinned registries/npm and is not offline.
 */
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  createReadStream, linkSync, lstatSync, mkdtempSync, readFileSync,
  realpathSync, rmSync
} from 'node:fs';
import path from 'node:path';

const sha256 = /^[a-f0-9]{64}$/u;
const gitSha = /^[a-f0-9]{40}$/u;
const image =
  /^((?:docker\.io\/)?(?:library\/)?node):24\.\d+\.\d+-bookworm-slim@sha256:([a-f0-9]{64})$/u;
const maxTarBytes = 8 * 1024 * 1024 * 1024;

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be explicitly provided.`);
  return value;
}
function runDocker(args) {
  const result = spawnSync('docker', args, {
    stdio: 'inherit', shell: false, timeout: 15 * 60 * 1000,
    env: { ...process.env, DOCKER_BUILDKIT: '1' }
  });
  if (result.error || result.status !== 0)
    throw new Error('Local OCI candidate build failed.');
}

const repository = realpathSync(path.resolve(import.meta.dirname, '..'));
const expectedSha = required('TOOLIP_RELEASE_GIT_SHA');
const version = required('TOOLIP_RELEASE_VERSION');
const builderImage = required('TOOLIP_BUILDER_IMAGE');
const runtimeImage = required('TOOLIP_RUNTIME_IMAGE');
const outputName = required('TOOLIP_OCI_OUTPUT');
const rawDirectory = required('TOOLIP_OCI_OUTPUT_DIR');

if (
  !gitSha.test(expectedSha) ||
  !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/u.test(version)
) throw new Error('Immutable release identity is invalid.');
for (const item of [builderImage, runtimeImage]) {
  const match = item.match(image);
  if (!match || !sha256.test(match[2]))
    throw new Error('Exact pinned Node 24 bookworm-slim images are required.');
}
if (
  path.basename(outputName) !== outputName ||
  !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tar$/u.test(outputName) ||
  !path.isAbsolute(rawDirectory)
) throw new Error('Output must be an absolute directory and simple .tar filename.');

const dirMeta = lstatSync(rawDirectory);
if (!dirMeta.isDirectory() || dirMeta.isSymbolicLink())
  throw new Error('OCI candidate output must be a regular directory.');
const directory = realpathSync(rawDirectory);
const relative = path.relative(repository, directory);
if (relative === '' ||
    (!relative.startsWith('..' + path.sep) && relative !== '..' &&
      !path.isAbsolute(relative)))
  throw new Error('OCI output directory must be outside the source checkout.');

const pkg = JSON.parse(
  readFileSync(path.join(repository, 'package.json'), 'utf8')
);
if (pkg.name !== 'toolip' || pkg.version !== version)
  throw new Error('Package version does not match the candidate release.');
const actualSha = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: repository, encoding: 'utf8', timeout: 5_000
}).trim();
if (actualSha !== expectedSha)
  throw new Error('Repository HEAD differs from the requested source SHA.');
if (execFileSync('git', ['status', '--porcelain'], {
  cwd: repository, encoding: 'utf8', timeout: 10_000
}).trim())
  throw new Error('OCI build requires a clean trusted checkout.');

const temp = mkdtempSync(path.join(directory, '.toolip-oci-'));
try {
  const stagedOutput = path.join(temp, outputName);
  const output = path.join(directory, outputName);
  runDocker([
    'buildx', 'build',
    '--file', 'distribution/oci/Dockerfile',
    '--platform', 'linux/amd64,linux/arm64',
    '--build-arg', `BUILDER_IMAGE=${builderImage}`,
    '--build-arg', `RUNTIME_IMAGE=${runtimeImage}`,
    '--build-arg', `SOURCE_GIT_SHA=${expectedSha}`,
    '--output', `type=oci,dest=${stagedOutput}`,
    '.'
  ]);
  const before = lstatSync(stagedOutput, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() ||
      before.size <= 0n || before.size > BigInt(maxTarBytes))
    throw new Error('OCI candidate is not a bounded regular artifact.');
  const hash = createHash('sha256');
  let readBytes = 0;
  for await (const bytes of createReadStream(stagedOutput)) {
    readBytes += bytes.length;
    if (readBytes > maxTarBytes) throw new Error('OCI image exceeds byte budget.');
    hash.update(bytes);
  }
  const after = lstatSync(stagedOutput, { bigint: true });
  if (BigInt(readBytes) !== before.size ||
      after.isSymbolicLink() || after.dev !== before.dev ||
      after.ino !== before.ino || after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs)
    throw new Error('OCI archive changed during integrity capture.');
  // Atomic no-clobber hard-link. Never write a generated OCI archive into
  // the checkout or overwrite a previously reviewed candidate.
  linkSync(stagedOutput, output);
  console.log(JSON.stringify({
    schema: 'toolip.dev/oci-candidate/v1',
    version, sourceGitSha: expectedSha,
    builderImage, runtimeImage,
    artifact: outputName,
    size: readBytes,
    sha256: hash.digest('hex'),
    architectures: ['linux/amd64', 'linux/arm64'],
    architectureRuntimeParityVerified: false,
    signed: false,
    attested: false,
    releaseApproved: false,
    published: false
  }, null, 2));
} finally {
  rmSync(temp, { recursive: true, force: true });
}
