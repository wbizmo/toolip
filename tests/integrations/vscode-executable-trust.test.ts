import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  trustedIdeExecutable
} from '../../integrations/vscode/src/trusted-executable.js';

const fixtures: string[] = [];
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((root) =>
    rm(root, { recursive: true, force: true })
  ));
});

describe('VS Code analyzer executable trust boundary', () => {
  it('accepts only explicit user-provisioned executable files outside all source workspaces', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vscode-trust-'));
    fixtures.push(root);
    const workspace = path.join(root, 'workspace');
    const external = path.join(root, 'private-toolip');
    const inside = path.join(workspace, 'toolip');
    await mkdir(workspace);
    await writeFile(external, '#!/bin/sh\nexit 0\n');
    await writeFile(inside, '#!/bin/sh\nexit 0\n');
    await chmod(external, 0o700);
    await chmod(inside, 0o700);

    expect(trustedIdeExecutable(external, [workspace])).toBe(external);
    expect(trustedIdeExecutable(inside, [workspace])).toBeUndefined();
    expect(trustedIdeExecutable('toolip', [workspace])).toBeUndefined();
    expect(trustedIdeExecutable(undefined, [workspace])).toBeUndefined();
  });

  it('does not allow symlinked executables or workspace-root aliases', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vscode-symlink-'));
    fixtures.push(root);
    const realProject = path.join(root, 'real-project');
    const aliasProject = path.join(root, 'alias-project');
    const ownedExecutable = path.join(realProject, 'toolip');
    const symlinkedExe = path.join(root, 'toolip-link');
    await mkdir(realProject);
    await writeFile(ownedExecutable, '#!/bin/sh\nexit 0\n');
    await chmod(ownedExecutable, 0o700);
    await symlink(realProject, aliasProject);
    await symlink(ownedExecutable, symlinkedExe);
    expect(trustedIdeExecutable(ownedExecutable, [aliasProject]))
      .toBeUndefined();
    expect(trustedIdeExecutable(symlinkedExe, [realProject]))
      .toBeUndefined();
  });

  it('rejects unrelated directories even when the path itself is absolute', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vscode-dir-'));
    fixtures.push(root);
    const workspace = path.join(root, 'workspace');
    await mkdir(workspace);
    expect(trustedIdeExecutable(root, [workspace])).toBeUndefined();
    expect(trustedIdeExecutable('/does-not-exist/toolip', [workspace]))
      .toBeUndefined();
  });
});
