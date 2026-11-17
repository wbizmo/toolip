import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const fixtureRoots: string[] = [];
afterEach(async () => {
  await Promise.all(fixtureRoots.splice(0).map((root) =>
    rm(root, { recursive: true, force: true })
  ));
});

describe('OCI distribution builder isolation and candidate identity', () => {
  it('keeps generated multiarch archives outside the clean repo and refuses overwrite', async () => {
    if (process.platform === 'win32') return;
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-oci-fake-'));
    fixtureRoots.push(root);
    const project = path.join(root, 'project');
    const scriptDir = path.join(project, 'scripts');
    const artifacts = path.join(root, 'artifacts');
    const executableDirectory = path.join(root, 'bin');
    await mkdir(scriptDir, { recursive: true });
    await mkdir(artifacts);
    await mkdir(executableDirectory);
    await writeFile(path.join(project, 'package.json'),
      JSON.stringify({ name: 'toolip', version: '3.2.1' }));
    await copyFile(path.resolve('scripts/build-oci-distribution.mjs'),
      path.join(scriptDir, 'build-oci-distribution.mjs'));
    const docker = path.join(executableDirectory, 'docker');
    await writeFile(docker, [
      '#!/usr/bin/env node',
      'const fs = require("node:fs");',
      'const args = process.argv.slice(2);',
      'const i = args.indexOf("--output");',
      'if (i < 0 || !args[i + 1].startsWith("type=oci,dest=")) process.exit(2);',
      'fs.writeFileSync(args[i + 1].slice("type=oci,dest=".length), "inert OCI fixture");'
    ].join('\n') + '\n');
    await chmod(docker, 0o755);
    execFileSync('git', ['init', '-q', project]);
    execFileSync('git', ['-C', project, 'add', '--all']);
    execFileSync('git', ['-C', project,
      '-c', 'user.name=Toolip Test',
      '-c', 'user.email=test@example.invalid',
      'commit', '-qm', 'synthetic OCI release source']);
    const sha = execFileSync('git', ['-C', project, 'rev-parse', 'HEAD'], {
      encoding: 'utf8'
    }).trim();
    const image = 'node:24.22.2-bookworm-slim@sha256:' + 'a'.repeat(64);
    const run = (outputDirectory: string) =>
      spawnSync(process.execPath, [
        path.join(scriptDir, 'build-oci-distribution.mjs')
      ], {
        encoding: 'utf8', shell: false, cwd: project,
        env: {
          ...process.env,
          PATH: executableDirectory + path.delimiter + process.env.PATH,
          TOOLIP_RELEASE_GIT_SHA: sha,
          TOOLIP_RELEASE_VERSION: '3.2.1',
          TOOLIP_BUILDER_IMAGE: image,
          TOOLIP_RUNTIME_IMAGE: image,
          TOOLIP_OCI_OUTPUT: 'toolip-3.2.1-oci.tar',
          TOOLIP_OCI_OUTPUT_DIR: outputDirectory
        }
      });
    const first = run(artifacts);
    expect(first.status).toBe(0);
    const info = JSON.parse(first.stdout) as {
      signed: boolean;
      attested: boolean;
      releaseApproved: boolean;
      published: boolean;
      sha256: string;
    };
    expect(info.signed).toBe(false);
    expect(info.attested).toBe(false);
    expect(info.releaseApproved).toBe(false);
    expect(info.published).toBe(false);
    expect(info.sha256).toMatch(/^[a-f0-9]{64}$/u);
    const saved = path.join(artifacts, 'toolip-3.2.1-oci.tar');
    expect(await readFile(saved, 'utf8')).toBe('inert OCI fixture');
    expect(execFileSync('git', ['-C', project, 'status', '--porcelain'], {
      encoding: 'utf8'
    }).trim()).toBe('');
    expect(run(artifacts).status).not.toBe(0);
    expect(await readFile(saved, 'utf8')).toBe('inert OCI fixture');
    expect(run(project).status).not.toBe(0);
  }, 30_000);
});
