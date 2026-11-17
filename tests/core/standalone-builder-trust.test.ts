import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) =>
    rm(root, { recursive: true, force: true })
  ));
});

describe('standalone build candidate trust and non-clobber boundaries', () => {
  it('uses a pinned private toolchain copy and leaves its Git source checkout clean', async () => {
    if (process.platform === 'win32') return;
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-build-inert-'));
    roots.push(root);
    const project = path.join(root, 'project');
    const scriptDir = path.join(project, 'scripts');
    const dist = path.join(project, 'dist', 'src');
    const artifacts = path.join(root, 'candidates');
    await mkdir(scriptDir, { recursive: true });
    await mkdir(dist, { recursive: true });
    await mkdir(artifacts, { recursive: true });
    await copyFile(
      path.resolve('scripts/build-standalone-candidate.mjs'),
      path.join(scriptDir, 'build-standalone-candidate.mjs')
    );
    await writeFile(path.join(project, 'package.json'),
      JSON.stringify({ name: 'toolip', version: '3.2.1' }));
    await writeFile(path.join(dist, 'index.js'),
      '#!/usr/bin/env node\nconsole.log("inert fixture");\n');
    const fakeBun = path.join(root, 'bun-fixture');
    const body = [
      '#!/usr/bin/env node',
      'const fs = require("node:fs");',
      'if (process.argv.includes("--version")) { console.log("1.2.3"); process.exit(0); }',
      'const i = process.argv.indexOf("--outfile");',
      'if (i < 0) process.exit(2);',
      'fs.writeFileSync(process.argv[i + 1], "inert compiled candidate");'
    ].join('\n') + '\n';
    await writeFile(fakeBun, body);
    await chmod(fakeBun, 0o755);

    execFileSync('git', ['init', '-q', project]);
    execFileSync('git', ['-C', project, 'add', '--all']);
    execFileSync('git', ['-C', project,
      '-c', 'user.name=Toolip Test',
      '-c', 'user.email=test@example.invalid',
      'commit', '-qm', 'synthetic release source']);
    const gitSha = execFileSync('git', ['-C', project, 'rev-parse', 'HEAD'],
      { encoding: 'utf8' }).trim();
    const bunHash = createHash('sha256').update(await readFile(fakeBun))
      .digest('hex');
    const run = (sha256: string) => spawnSync(process.execPath, [
      path.join(scriptDir, 'build-standalone-candidate.mjs')
    ], {
      encoding: 'utf8', shell: false, cwd: project,
      env: {
        ...process.env,
        TOOLIP_BUN_BINARY: fakeBun,
        TOOLIP_BUN_VERSION: '1.2.3',
        TOOLIP_BUN_SHA256: sha256,
        TOOLIP_RELEASE_GIT_SHA: gitSha,
        TOOLIP_RELEASE_VERSION: '3.2.1',
        TOOLIP_STANDALONE_TARGET: 'bun-linux-x64',
        TOOLIP_STANDALONE_CANDIDATE_DIR: artifacts
      }
    });
    const mismatched = run('0'.repeat(64));
    expect(mismatched.status).not.toBe(0);
    expect(await readFile(fakeBun, 'utf8')).toBe(body);
    const first = run(bunHash);
    expect(first.status).toBe(0);
    const data = JSON.parse(first.stdout) as {
      signed: boolean;
      verified: boolean;
      runtimeParityTested: boolean;
      published: boolean;
    };
    expect(data.signed).toBe(false);
    expect(data.verified).toBe(false);
    expect(data.runtimeParityTested).toBe(false);
    expect(data.published).toBe(false);
    const output = path.join(artifacts, 'toolip-3.2.1-bun-linux-x64');
    expect(await readFile(output, 'utf8')).toBe('inert compiled candidate');
    expect(execFileSync('git', ['-C', project, 'status', '--porcelain'],
      { encoding: 'utf8' }).trim()).toBe('');
    const duplicate = run(bunHash);
    expect(duplicate.status).not.toBe(0);
    expect(await readFile(output, 'utf8')).toBe('inert compiled candidate');
  }, 30_000);
});
