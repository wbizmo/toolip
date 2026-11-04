import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const script = path.resolve('scripts/verify-node.mjs');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const run = (version: string, entry = script) =>
  spawnSync(process.execPath, [entry, version], { encoding: 'utf8' });

describe('verify-node.mjs (issue #92 negative/positive fixtures)', () => {
  it.each([
    ['22.23.3', 1],
    ['24.22.0', 1],
    ['23.5.0', 1],
    ['25.0.0', 1],
    ['22.23.4', 0],
    ['24.22.1', 0],
    ['24.22.2', 0]
  ])('version %s exits %i', (version, code) => {
    expect(run(version).status).toBe(code);
  });

  it('runs in a fresh checkout with no node_modules (pre-npm-ci bootstrap)', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'toolip-bootstrap-'));
    dirs.push(dir);
    mkdirSync(path.join(dir, 'scripts'));
    mkdirSync(path.join(dir, 'security'));
    cpSync(script, path.join(dir, 'scripts/verify-node.mjs'));
    cpSync(
      'security/runtime-floors.json',
      path.join(dir, 'security/runtime-floors.json')
    );
    cpSync('package.json', path.join(dir, 'package.json'));
    const result = run('24.22.2', path.join(dir, 'scripts/verify-node.mjs'));
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
  });
});
