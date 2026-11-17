import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) =>
    rm(root, { recursive: true, force: true })
  ));
});

async function createFixture(target: 'bun-darwin-x64' | 'bun-windows-x64') {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-bun-candidate-'));
  roots.push(root);
  const candidates = path.join(root, 'candidates');
  const artifacts = path.join(root, 'artifacts');
  await mkdir(candidates);
  await mkdir(artifacts);
  const version = '3.2.1';
  const filename = `toolip-${version}-${target}${target.startsWith('bun-windows') ? '.exe' : ''}`;
  const body = Buffer.from('inert synthetic standalone artifact; never executed', 'utf8');
  await writeFile(path.join(candidates, filename), body);
  const result = spawnSync(process.execPath, [
    path.resolve('scripts/package-standalone-candidate.mjs')
  ], {
    encoding: 'utf8',
    shell: false,
    env: {
      ...process.env,
      TOOLIP_RELEASE_VERSION: version,
      TOOLIP_STANDALONE_TARGET: target,
      TOOLIP_STANDALONE_CANDIDATE_DIR: candidates,
      TOOLIP_DISTRIBUTION_ASSETS_DIR: artifacts
    }
  });
  return { result, artifacts, candidates, version, body };
}

describe('portable standalone candidate archives', () => {
  it('produces a deterministic root-file tar.gz with no symlink or additional members', async () => {
    const fixture = await createFixture('bun-darwin-x64');
    expect(fixture.result.status).toBe(0);
    const meta = JSON.parse(fixture.result.stdout) as {
      artifact: string;
      signed: boolean;
      releaseApproved: boolean;
    };
    expect(meta.artifact).toBe('toolip-3.2.1-darwin-x64.tar.gz');
    expect(meta.signed).toBe(false);
    expect(meta.releaseApproved).toBe(false);
    const compressed = await readFile(path.join(fixture.artifacts, meta.artifact));
    const tar = gunzipSync(compressed);
    expect(tar.subarray(0, 6).toString('utf8')).toBe('toolip');
    expect(tar[156]).toBe(0x30);
    const header = Buffer.from(tar.subarray(0, 512));
    const recorded = Number.parseInt(
      header.subarray(148, 154).toString('ascii'), 8
    );
    expect(header[154]).toBe(0);
    expect(header[155]).toBe(0x20);
    header.fill(0x20, 148, 156);
    expect(recorded).toBe(
      header.reduce((sum, byte) => sum + byte, 0)
    );
    const payload = tar.subarray(512, 512 + fixture.body.length);
    expect(payload).toEqual(fixture.body);
    expect(tar.subarray(-1024).every((value) => value === 0)).toBe(true);
  });

  it('produces a single-entry Windows ZIP with a bounded uncompressed payload', async () => {
    const fixture = await createFixture('bun-windows-x64');
    expect(fixture.result.status).toBe(0);
    const meta = JSON.parse(fixture.result.stdout) as { artifact: string };
    expect(meta.artifact).toBe('toolip-3.2.1-windows-x64.zip');
    const zip = await readFile(path.join(fixture.artifacts, meta.artifact));
    expect(zip.readUInt32LE(0)).toBe(0x04034b50);
    expect(zip.readUInt16LE(8)).toBe(0); // stored, not deflated
    const nameLength = zip.readUInt16LE(26);
    expect(zip.subarray(30, 30 + nameLength).toString()).toBe('toolip.exe');
    expect(zip.readUInt32LE(22)).toBe(fixture.body.length);
    expect(zip.subarray(30 + nameLength, 30 + nameLength + fixture.body.length))
      .toEqual(fixture.body);
    const central = zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    expect(central).toBeGreaterThan(0);
    expect(zip.readUInt32LE(central + 38)).toBe((0o100755 * 0x10000) >>> 0);
    expect(zip.readUInt32LE(zip.length - 22)).toBe(0x06054b50);
  });

  it('refuses unsupported targets and cannot overwrite an existing release archive', async () => {
    const fixture = await createFixture('bun-darwin-x64');
    expect(fixture.result.status).toBe(0);
    const output = path.join(
      fixture.artifacts, 'toolip-3.2.1-darwin-x64.tar.gz'
    );
    const original = await readFile(output);
    const duplicate = spawnSync(process.execPath, [
      path.resolve('scripts/package-standalone-candidate.mjs')
    ], {
      encoding: 'utf8',
      shell: false,
      env: {
        ...process.env,
        TOOLIP_RELEASE_VERSION: '3.2.1',
        TOOLIP_STANDALONE_TARGET: 'bun-darwin-x64',
        TOOLIP_STANDALONE_CANDIDATE_DIR: fixture.candidates,
        TOOLIP_DISTRIBUTION_ASSETS_DIR: fixture.artifacts
      }
    });
    expect(duplicate.status).not.toBe(0);
    expect(await readFile(output)).toEqual(original);

    const unexpected = spawnSync(process.execPath, [
      path.resolve('scripts/package-standalone-candidate.mjs')
    ], {
      encoding: 'utf8',
      shell: false,
      env: {
        ...process.env,
        TOOLIP_RELEASE_VERSION: '3.2.1',
        TOOLIP_STANDALONE_TARGET: 'bun-darwin-unknown',
        TOOLIP_STANDALONE_CANDIDATE_DIR: fixture.candidates,
        TOOLIP_DISTRIBUTION_ASSETS_DIR: fixture.artifacts
      }
    });
    expect(unexpected.status).not.toBe(0);
  });
});
