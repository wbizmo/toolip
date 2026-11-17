#!/usr/bin/env node
/**
 * Local, UNSIGNED Bun standalone feasibility candidate builder (#111).
 * No toolchain download, release publication, artifact signing, or assertion
 * of cross-platform runtime compatibility. A separately owned trusted
 * release gate must verify and publish any final executable.
 */
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  constants, chmodSync, closeSync, copyFileSync, fstatSync, linkSync, lstatSync, mkdtempSync, openSync,
  readFileSync, readSync, realpathSync, rmSync
} from 'node:fs';
import path from 'node:path';

const repository = realpathSync(path.resolve(import.meta.dirname, '..'));
const validSha = /^[a-f0-9]{40}$/u;
const validDigest = /^[a-f0-9]{64}$/u;
const validVersion = /^[0-9]+\.[0-9]+\.[0-9]+$/u;
const targets = new Set([
  'bun-linux-x64', 'bun-linux-arm64',
  'bun-linux-x64-musl', 'bun-linux-arm64-musl',
  'bun-darwin-x64', 'bun-darwin-arm64',
  'bun-windows-x64'
]);
const maxBunBytes = 512 * 1024 * 1024;
const maxCandidateBytes = 2 * 1024 * 1024 * 1024;

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Standalone candidate requires ${name}.`);
  return value;
}

/** Hash a single unchanging regular inode; reject filename swaps. */
function digestRegularFile(filePath, maxBytes) {
  const before = lstatSync(filePath, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile() ||
      before.size <= 0n || before.size > BigInt(maxBytes))
    throw new Error('The candidate or toolchain is not a bounded regular file.');
  const fd = openSync(filePath, constants.O_RDONLY |
    (process.platform === 'win32' ? 0 : (constants.O_NOFOLLOW ?? 0)));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev ||
        opened.ino !== before.ino || opened.size !== before.size ||
        opened.mtimeNs !== before.mtimeNs || opened.ctimeNs !== before.ctimeNs)
      throw new Error('File changed while opening its content.');
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    const size = Number(opened.size);
    while (position < size) {
      const bytes = readSync(fd, buffer, 0,
        Math.min(buffer.length, size - position), position);
      if (bytes === 0) throw new Error('File was truncated during digest verification.');
      hash.update(buffer.subarray(0, bytes));
      position += bytes;
    }
    const finished = fstatSync(fd, { bigint: true });
    const named = lstatSync(filePath, { bigint: true });
    if (finished.dev !== opened.dev || finished.ino !== opened.ino ||
        finished.size !== opened.size || finished.mtimeNs !== opened.mtimeNs ||
        finished.ctimeNs !== opened.ctimeNs ||
        named.isSymbolicLink() || named.dev !== opened.dev ||
        named.ino !== opened.ino || named.size !== opened.size ||
        named.mtimeNs !== opened.mtimeNs || named.ctimeNs !== opened.ctimeNs)
      throw new Error('File changed during digest verification.');
    return { sha256: hash.digest('hex'), bytes: size };
  } finally {
    closeSync(fd);
  }
}

const rawBun = required('TOOLIP_BUN_BINARY');
const bunSha256 = required('TOOLIP_BUN_SHA256');
const bunVersion = required('TOOLIP_BUN_VERSION');
const sourceSha = required('TOOLIP_RELEASE_GIT_SHA');
const version = required('TOOLIP_RELEASE_VERSION');
const target = required('TOOLIP_STANDALONE_TARGET');
const rawDestination = required('TOOLIP_STANDALONE_CANDIDATE_DIR');
if (
  !path.isAbsolute(rawBun) ||
  !path.isAbsolute(rawDestination) ||
  !validDigest.test(bunSha256) ||
  !validSha.test(sourceSha) ||
  !validVersion.test(bunVersion) ||
  !validVersion.test(version) ||
  !targets.has(target)
) throw new Error('Immutable toolchain/release identity or target is invalid.');

const directory = realpathSync(rawDestination);
const info = lstatSync(rawDestination);
if (!info.isDirectory() || info.isSymbolicLink())
  throw new Error('Candidate output must be an existing real directory.');
const relativeToRepo = path.relative(repository, directory);
if (
  relativeToRepo === '' ||
  (!relativeToRepo.startsWith('..' + path.sep) &&
    relativeToRepo !== '..' && !path.isAbsolute(relativeToRepo))
) throw new Error('Candidate output must be outside the source checkout.');

const bunPath = realpathSync(rawBun);
if (bunPath !== rawBun)
  throw new Error('Toolchain path must not contain symlinked components.');
const bun = digestRegularFile(bunPath, maxBunBytes);
if (bun.sha256 !== bunSha256)
  throw new Error('Bun executable does not match the independently pinned SHA-256.');
 const actualSha = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: repository, encoding: 'utf8', timeout: 5_000
}).trim();
if (actualSha !== sourceSha)
  throw new Error('Candidate source Git SHA differs from exact expected revision.');
if (execFileSync('git', ['status', '--porcelain'], {
  cwd: repository, encoding: 'utf8', timeout: 10_000
}).trim()) throw new Error('Standalone candidate requires a clean source tree.');
const pkg = JSON.parse(readFileSync(path.join(repository, 'package.json'), 'utf8'));
if (pkg.name !== 'toolip' || pkg.version !== version)
  throw new Error('Requested release version differs from the source package.');

const input = path.join(repository, 'dist', 'src', 'index.js');
if (!lstatSync(input).isFile())
  throw new Error('Build the trusted Toolip CLI before the standalone feasibility spike.');

const filename =
  `toolip-${version}-${target}${target.startsWith('bun-windows') ? '.exe' : ''}`;
const destination = path.join(directory, filename);
const temporaryDirectory = mkdtempSync(path.join(directory, '.toolip-build-'));
try {
  // Execute only a private copy whose bytes are independently re-hashed.
  // A concurrent replacement of the original toolchain path cannot affect
  // which executable is invoked after this point.
  const verifiedBun = path.join(
    temporaryDirectory, process.platform === 'win32' ? 'bun-tool.exe' : 'bun-tool'
  );
  copyFileSync(bunPath, verifiedBun, constants.COPYFILE_EXCL);
  chmodSync(verifiedBun, 0o700);
  const copied = digestRegularFile(verifiedBun, maxBunBytes);
  if (copied.sha256 !== bunSha256)
    throw new Error('Private Bun toolchain copy differs from the pinned digest.');
  const actualBun = execFileSync(verifiedBun, ['--version'], {
    encoding: 'utf8', timeout: 5_000
  }).trim();
  if (actualBun !== bunVersion)
    throw new Error('Verified Bun version differs from the pinned toolchain.');
  const candidate = path.join(temporaryDirectory, filename);
  const result = spawnSync(verifiedBun, [
    'build', input, '--compile', '--target', target, '--outfile', candidate
  ], {
    cwd: repository, timeout: 10 * 60 * 1000,
    shell: false, stdio: 'inherit'
  });
  if (result.error || result.status !== 0)
    throw new Error('Bun standalone feasibility compilation failed.');
  const generated = digestRegularFile(candidate, maxCandidateBytes);
  // Hard-link on the same output volume with fail-if-exists semantics. Do not
  // overwrite a previously produced candidate or silently change its digest.
  linkSync(candidate, destination);
  console.log(JSON.stringify({
    schema: 'toolip.dev/standalone-candidate/v1',
    verified: false,
    signed: false,
    releaseApproved: false,
    sourceSha,
    packageVersion: version,
    bunVersion: actualBun,
    bunSha256,
    target, filename,
    bytes: generated.bytes,
    sha256: generated.sha256,
    runtimeParityTested: false,
    published: false
  }, null, 2));
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
