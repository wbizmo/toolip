import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const script = path.resolve('scripts/verify-lockfile.mjs');
const floors = path.resolve('security/advisory-floors.json');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const INTEGRITY = `sha512-${'A'.repeat(86)}==`;

type Entry = {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
};
type Lock = {
  name: string;
  version: string;
  lockfileVersion: number;
  packages: Record<string, Entry>;
};
type Manifest = { name: string; version: string };

function lockWith(mutate: (lock: Lock, manifest: Manifest) => void) {
  const manifest: Manifest = { name: 'toolip', version: '3.2.1' };
  const lock: Lock = {
    name: 'toolip',
    version: '3.2.1',
    lockfileVersion: 3,
    packages: {
      '': { name: 'toolip', version: '3.2.1' },
      'node_modules/undici': {
        version: '8.12.3',
        resolved: 'https://registry.npmjs.org/undici/-/undici-8.12.3.tgz',
        integrity: INTEGRITY
      }
    }
  };
  mutate(lock, manifest);
  const dir = mkdtempSync(path.join(os.tmpdir(), 'toolip-lock-'));
  dirs.push(dir);
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify(manifest));
  writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify(lock));
  return spawnSync(process.execPath, [script], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, ADVISORY_FLOORS: floors }
  });
}

describe('lockfile integrity and version sync (issues #50, #51, #52)', () => {
  it('accepts a consistent lockfile', () => {
    expect(lockWith(() => {}).status).toBe(0);
  });

  it('fails when the top-level lockfile version is skewed', () => {
    const r = lockWith((lock) => {
      lock.version = '2.2.0';
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('lockfile version 2.2.0');
  });

  it('fails when only the lockfile root package version is skewed', () => {
    const r = lockWith((lock) => {
      lock.packages[''].version = '2.2.0';
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('root package version');
  });

  it('fails when package.json alone is skewed', () => {
    const r = lockWith((_lock, manifest) => {
      manifest.version = '3.2.2';
    });
    expect(r.status).toBe(1);
  });

  it('fails if the vulnerable undici 6.28.1 re-enters the lockfile', () => {
    const r = lockWith((lock) => {
      lock.packages['node_modules/node-gyp/node_modules/undici'] = {
        version: '6.28.1',
        resolved: 'https://registry.npmjs.org/undici/-/undici-6.28.1.tgz',
        integrity: INTEGRITY
      };
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('undici@6.28.1');
    expect(r.stderr).toContain('GHSA-');
  });

  it.each([
    ['@modelcontextprotocol/sdk', '1.29.0'],
    ['zod', '3.25.76'],
    ['proxy-addr', '2.0.7']
  ])('fails for known-vulnerable %s@%s', (name, version) => {
    const r = lockWith((lock) => {
      lock.packages[`node_modules/${name}`] = {
        version,
        resolved: `https://registry.npmjs.org/${name}/-/x-${version}.tgz`,
        integrity: INTEGRITY
      };
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(`${name}@${version}`);
  });

  it('rejects non-registry sources and weak integrity hashes', () => {
    const r = lockWith((lock) => {
      lock.packages['node_modules/evil'] = {
        version: '1.0.0',
        resolved: 'git+https://example.com/evil.git',
        integrity: 'sha1-AAAA'
      };
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('resolved outside');
    expect(r.stderr).toContain('weak integrity');
  });

  it('keeps the real committed lockfile clean', () => {
    const real = spawnSync(process.execPath, [script], { encoding: 'utf8' });
    expect(real.stderr).toBe('');
    expect(real.status).toBe(0);
    expect(JSON.parse(readFileSync('package-lock.json', 'utf8')).version).toBe(
      JSON.parse(readFileSync('package.json', 'utf8')).version
    );
  });
});
