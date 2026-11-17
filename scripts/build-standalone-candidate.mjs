#!/usr/bin/env node
/*
 * Feasibility-only runtime-embedded standalone candidate builder (#111).
 * It requires a separately provisioned, exact-version Bun executable and
 * does not download Bun, publish assets or assert cross-platform parity.
 */
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { createReadStream, readFileSync, statSync, mkdirSync } from 'node:fs';
import path from 'node:path';

const repo = path.resolve(import.meta.dirname, '..');
const targets = new Set([
  'bun-linux-x64',
  'bun-linux-arm64',
  'bun-linux-x64-musl',
  'bun-linux-arm64-musl',
  'bun-darwin-x64',
  'bun-darwin-arm64',
  'bun-windows-x64'
]);

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for a local candidate.`);
  return value;
}

const bunBinary = path.resolve(required('TOOLIP_BUN_BINARY'));
const pinnedVersion = required('TOOLIP_BUN_VERSION');
const target = required('TOOLIP_STANDALONE_TARGET');
const sourceSha = required('TOOLIP_RELEASE_GIT_SHA');
if (!targets.has(target))
  throw new Error('Standalone candidate target is not supported.');
if (!/^\d+\.\d+\.\d+$/.test(pinnedVersion) ||
    !/^[a-f0-9]{40}$/u.test(sourceSha))
  throw new Error('Bun toolchain version or source SHA is invalid.');
if (!path.isAbsolute(required('TOOLIP_BUN_BINARY')) ||
    !statSync(bunBinary).isFile())
  throw new Error('An operator-provisioned absolute Bun executable is required.');
const actualBun = execFileSync(bunBinary, ['--version'], {
  encoding: 'utf8', timeout: 5_000
}).trim();
if (actualBun !== pinnedVersion)
  throw new Error('Installed Bun executable version does not match pinned build requirement.');
const actualSha = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: repo, encoding: 'utf8', timeout: 5_000
}).trim();
if (actualSha !== sourceSha)
  throw new Error('Standalone source revision differs from the expected Git SHA.');
const status = execFileSync('git', ['status', '--porcelain'], {
  cwd: repo, encoding: 'utf8', timeout: 10_000
}).trim();
if (status) throw new Error('Standalone candidate requires a clean source tree.');
const pkg = JSON.parse(readFileSync(path.join(repo, 'package.json'), 'utf8'));
const input = path.join(repo, 'dist/src/index.js');
if (!statSync(input).isFile())
  throw new Error('Build the verified Toolip CLI before the standalone feasibility spike.');
const directory = path.join(repo, 'standalone-candidates');
mkdirSync(directory, { recursive: true, mode: 0o700 });
const filename = `toolip-${pkg.version}-${target}${target.startsWith('bun-windows') ? '.exe' : ''}`;
const output = path.join(directory, filename);
const result = spawnSync(bunBinary, [
  'build', input,
  '--compile', '--target', target,
  '--outfile', output
], {
  cwd: repo, timeout: 10 * 60 * 1000,
  shell: false, stdio: 'inherit'
});
if (result.error || result.status !== 0)
  throw new Error('Standalone candidate compilation failed.');
const hash = createHash('sha256');
const stream = createReadStream(output);
let totalBytes = 0;
for await (const chunk of stream) {
  totalBytes += chunk.length;
  hash.update(chunk);
}
if (!totalBytes || totalBytes > 2 * 1024 * 1024 * 1024)
  throw new Error('Standalone candidate output size is invalid.');
console.log(JSON.stringify({
  schema: 'toolip.dev/standalone-candidate/v1',
  verified: false,
  signed: false,
  releaseApproved: false,
  sourceSha,
  packageVersion: pkg.version,
  bunVersion: actualBun,
  target,
  filename,
  bytes: totalBytes,
  sha256: hash.digest('hex')
}, null, 2));
