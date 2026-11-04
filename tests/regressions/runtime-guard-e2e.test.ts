import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

function cli(nodeVersion: string | undefined, ...args: string[]) {
  return spawnSync(
    process.execPath,
    [
      '--import',
      // Windows requires a file:// URL for absolute --import specifiers.
      pathToFileURL(path.resolve('tests/fixtures/fake-node-version.mjs')).href,
      '--import',
      'tsx',
      'src/index.ts',
      ...args
    ],
    {
      encoding: 'utf8',
      env: {
        ...process.env,
        TOOLIP_ALLOW_UNPATCHED_NODE: '',
        ...(nodeVersion ? { TOOLIP_TEST_NODE_VERSION: nodeVersion } : {})
      }
    }
  );
}

describe('real CLI entry point on a simulated unpatched runtime (issue #92)', () => {
  it.each([
    ['-o', '--help'],
    ['-o', '-h'],
    ['-o', 'self-test']
  ])(
    'refuses `scan %s %s` and never runs the scan or writes the report',
    (flag, value) => {
      const project = mkdtempSync(path.join(os.tmpdir(), 'toolip-e2e-'));
      dirs.push(project);
      writeFileSync(
        path.join(project, 'package.json'),
        '{"name":"x","version":"1.0.0"}'
      );
      const result = cli('22.23.3', 'scan', '-p', project, flag, value);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('Toolip refused to run');
      expect(readdirSync(project)).toEqual(['package.json']);
    },
    30_000
  );

  it('still prints the version (with a warning) and runs self-test', () => {
    const version = cli('24.22.0', '--version');
    expect(version.status).toBe(0);
    expect(version.stderr).toContain('Toolip warning');
    expect(version.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);

    const selfTest = cli('24.22.0', 'self-test');
    expect(selfTest.status).toBe(1);
    expect(selfTest.stdout).toContain('Supported patched Node.js');
  }, 30_000);

  it('runs normally on a patched runtime without a warning', () => {
    const result = cli('24.22.2', '--version');
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
  }, 30_000);
});
