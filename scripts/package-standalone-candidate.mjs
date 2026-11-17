#!/usr/bin/env node
/**
 * Convert one operator-built Bun executable candidate into the exact
 * reproducible tar.gz or ZIP container consumed by the signed distribution
 * manifest and the optional installers. No source execution or publication.
 */
import { createHash } from 'node:crypto';
import { constants, createWriteStream } from 'node:fs';
import { lstat, open, rm } from 'node:fs/promises';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGzip } from 'node:zlib';

const sourceTargets = new Map([
  ['bun-darwin-arm64', 'darwin-arm64'],
  ['bun-darwin-x64', 'darwin-x64'],
  ['bun-linux-arm64', 'linux-arm64-gnu'],
  ['bun-linux-x64', 'linux-x64-gnu'],
  ['bun-linux-arm64-musl', 'linux-arm64-musl'],
  ['bun-linux-x64-musl', 'linux-x64-musl'],
  ['bun-windows-x64', 'windows-x64']
]);
const maximumExecutableBytes = 1024 * 1024 * 1024;

function required(key) {
  const value = process.env[key];
  if (!value) throw new Error(`Standalone packaging requires ${key}.`);
  return value;
}
const version = required('TOOLIP_RELEASE_VERSION');
const bunTarget = required('TOOLIP_STANDALONE_TARGET');
const sourceDirectory = required('TOOLIP_STANDALONE_CANDIDATE_DIR');
const destinationDirectory = required('TOOLIP_DISTRIBUTION_ASSETS_DIR');
if (!/^\d+\.\d+\.\d+$/u.test(version) ||
    !sourceTargets.has(bunTarget) ||
    !path.isAbsolute(sourceDirectory) ||
    !path.isAbsolute(destinationDirectory))
  throw new Error('Exact release, Bun candidate target and absolute directories required.');
const target = sourceTargets.get(bunTarget);
const windows = target.startsWith('windows-');
const rawName = `toolip-${version}-${bunTarget}${windows ? '.exe' : ''}`;
const sourcePath = path.join(sourceDirectory, rawName);
const artifactName = `toolip-${version}-${target}.${windows ? 'zip' : 'tar.gz'}`;
const artifactPath = path.join(destinationDirectory, artifactName);

function putString(buffer, start, width, text) {
  const bytes = Buffer.from(text, 'ascii');
  if (bytes.length > width) throw new Error('Archive field exceeds its width.');
  bytes.copy(buffer, start);
}
function putOctal(buffer, start, width, value) {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error('Invalid tar numeric field.');
  const digits = value.toString(8).padStart(width - 1, '0');
  if (digits.length > width - 1) throw new Error('Tar field overflow.');
  putString(buffer, start, width, digits);
}
function tarHeader(name, size) {
  const header = Buffer.alloc(512);
  putString(header, 0, 100, name);
  putOctal(header, 100, 8, 0o755);
  putOctal(header, 108, 8, 0);
  putOctal(header, 116, 8, 0);
  putOctal(header, 124, 12, size);
  putOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = 0x30; // regular file
  putString(header, 257, 6, 'ustar');
  putString(header, 263, 2, '00');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  putOctal(header, 148, 8, checksum);
  return header;
}

const crcTable = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++)
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : c >>> 1;
  crcTable[i] = c >>> 0;
}

async function crc32(handle, size) {
  let crc = 0xffffffff;
  let readBytes = 0;
  for await (const chunk of handle.createReadStream({ start: 0, autoClose: false })) {
    readBytes += chunk.length;
    if (readBytes > size) throw new Error('Executable grew during CRC calculation.');
    for (const byte of chunk)
      crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff];
  }
  if (readBytes !== size) throw new Error('Executable truncated during CRC calculation.');
  return (crc ^ 0xffffffff) >>> 0;
}

function zipHeaders(name, size, checksum) {
  const filename = Buffer.from(name, 'utf8');
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(0, 8); // stored, no compression
  local.writeUInt32LE(checksum, 14);
  local.writeUInt32LE(size, 18);
  local.writeUInt32LE(size, 22);
  local.writeUInt16LE(filename.length, 26);

  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE((3 << 8) | 20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt32LE(checksum, 16);
  central.writeUInt32LE(size, 20);
  central.writeUInt32LE(size, 24);
  central.writeUInt16LE(filename.length, 28);
  central.writeUInt32LE((0o100755 * 0x10000) >>> 0, 38);
  central.writeUInt32LE(0, 42);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length + filename.length, 12);
  end.writeUInt32LE(local.length + filename.length + size, 16);
  return { local, central, filename, end };
}

const folder = await lstat(destinationDirectory);
if (!folder.isDirectory() || folder.isSymbolicLink())
  throw new Error('Release asset output must be an existing regular directory.');
const before = await lstat(sourcePath, { bigint: true });
if (!before.isFile() || before.isSymbolicLink() ||
    before.size < 1n || before.size > BigInt(maximumExecutableBytes))
  throw new Error('Standalone candidate must be a bounded real executable file.');
const descriptor = await open(
  sourcePath,
  constants.O_RDONLY |
    (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
);
let created = false;
try {
  const opened = await descriptor.stat({ bigint: true });
  if (!opened.isFile() || opened.ino !== before.ino ||
      opened.dev !== before.dev || opened.size !== before.size ||
      opened.mtimeNs !== before.mtimeNs || opened.ctimeNs !== before.ctimeNs)
    throw new Error('Executable changed before packaging.');

  const size = Number(before.size);
  let bodyBytes = 0;
  const payload = async function* () {
    if (windows) {
      const checksum = await crc32(descriptor, size);
      const parts = zipHeaders('toolip.exe', size, checksum);
      yield parts.local;
      yield parts.filename;
      for await (const chunk of descriptor.createReadStream({
        start: 0, autoClose: false
      })) {
        bodyBytes += chunk.length;
        if (bodyBytes > size) throw new Error('Executable changed while streaming ZIP.');
        yield chunk;
      }
      yield parts.central;
      yield parts.filename;
      yield parts.end;
    } else {
      yield tarHeader('toolip', size);
      for await (const chunk of descriptor.createReadStream({
        start: 0, autoClose: false
      })) {
        bodyBytes += chunk.length;
        if (bodyBytes > size) throw new Error('Executable changed while streaming tar.');
        yield chunk;
      }
      const padding = (512 - (size % 512)) % 512;
      if (padding) yield Buffer.alloc(padding);
      yield Buffer.alloc(1024);
    }
  };

  const stream = createWriteStream(artifactPath, {
    flags: 'wx', mode: 0o600
  });
  created = true;
  if (windows) await pipeline(Readable.from(payload()), stream);
  else await pipeline(
    Readable.from(payload()),
    createGzip({ level: 9, mtime: 0 }),
    stream
  );
  if (bodyBytes !== size)
    throw new Error('Packaged executable content length is inconsistent.');
  const after = await descriptor.stat({ bigint: true });
  const named = await lstat(sourcePath, { bigint: true });
  if (opened.dev !== after.dev || opened.ino !== after.ino ||
      opened.size !== after.size || opened.mtimeNs !== after.mtimeNs ||
      opened.ctimeNs !== after.ctimeNs ||
      named.isSymbolicLink() || named.dev !== opened.dev ||
      named.ino !== opened.ino || named.size !== opened.size ||
      named.mtimeNs !== opened.mtimeNs || named.ctimeNs !== opened.ctimeNs)
    throw new Error('Executable changed during artifact packaging.');
} catch (error) {
  if (created) await rm(artifactPath, { force: true });
  throw error;
} finally {
  await descriptor.close();
}

const artifact = await open(artifactPath, constants.O_RDONLY);
let bytes = 0;
const hash = createHash('sha256');
try {
  for await (const chunk of artifact.createReadStream({ autoClose: false })) {
    bytes += chunk.length;
    hash.update(chunk);
  }
} finally {
  await artifact.close();
}
console.log(JSON.stringify({
  schema: 'toolip.dev/distribution-candidate/v1',
  target,
  sourceGitSha: process.env.TOOLIP_RELEASE_GIT_SHA ?? null,
  sourceBinary: rawName,
  artifact: artifactName,
  artifactSize: bytes,
  sha256: hash.digest('hex'),
  executableRuntimeParityVerified: false,
  signed: false,
  releaseApproved: false,
  published: false
}, null, 2));
