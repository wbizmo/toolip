#!/usr/bin/env node
/*
 * Builds a LOCAL, UNSIGNED OCI CANDIDATE for review.
 * Never pushes an image, creates a tag, generates trust claims or enables
 * privileged Docker access. A separate approved release pipeline must
 * validate Stage A, provenance, SBOM, signing and runtime parity.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const sha256 = /^[a-f0-9]{64}$/u;
const gitSha = /^[a-f0-9]{40}$/u;
const image = /^((?:docker\.io\/)?(?:library\/)?node):24\.\d+\.\d+-bookworm-slim@sha256:([a-f0-9]{64})$/u;

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be explicitly provided.`);
  return value;
}

function run(args) {
  const result = spawnSync('docker', args, {
    stdio: 'inherit',
    shell: false,
    timeout: 15 * 60 * 1000,
    env: { ...process.env, DOCKER_BUILDKIT: '1' }
  });
  if (result.error) throw new Error('Docker invocation failed.');
  if (result.status !== 0)
    throw new Error('Docker candidate build failed.');
}

const repository = path.resolve(import.meta.dirname, '..');
const [expectedSha, version, builderImage, runtimeImage, outputName] = [
  required('TOOLIP_RELEASE_GIT_SHA'),
  required('TOOLIP_RELEASE_VERSION'),
  required('TOOLIP_BUILDER_IMAGE'),
  required('TOOLIP_RUNTIME_IMAGE'),
  required('TOOLIP_OCI_OUTPUT')
];
if (!gitSha.test(expectedSha) || !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/u.test(version))
  throw new Error('Expected immutable release revision/version is invalid.');
for (const item of [builderImage, runtimeImage]) {
  const match = item.match(image);
  if (!match || !sha256.test(match[2]))
    throw new Error('A digest-pinned Node 24 bookworm-slim image is required.');
}
if (path.basename(outputName) !== outputName ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tar$/u.test(outputName))
  throw new Error('OCI candidate output must be a simple local .tar filename.');
const packageData = JSON.parse(readFileSync(path.join(repository, 'package.json'), 'utf8'));
if (packageData.version !== version)
  throw new Error('Toolip package version is not the expected distribution version.');
const actualSha = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: repository, encoding: 'utf8'
}).trim();
if (actualSha !== expectedSha)
  throw new Error('Repository HEAD differs from the requested immutable commit.');
const dirty = execFileSync('git', ['status', '--porcelain'], {
  cwd: repository, encoding: 'utf8'
}).trim();
if (dirty)
  throw new Error('A local OCI candidate requires a clean working tree.');
const outputPath = path.join(repository, outputName);
run([
  'buildx', 'build',
  '--file', 'distribution/oci/Dockerfile',
  '--platform', 'linux/amd64,linux/arm64',
  '--build-arg', `BUILDER_IMAGE=${builderImage}`,
  '--build-arg', `RUNTIME_IMAGE=${runtimeImage}`,
  '--build-arg', `SOURCE_GIT_SHA=${expectedSha}`,
  '--output', `type=oci,dest=${outputPath}`,
  '.'
]);
console.log('Local unsigned OCI candidate generated. NOT an approved release.');
