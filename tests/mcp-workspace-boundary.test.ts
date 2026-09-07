import { mkdtemp, mkdir, realpath, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createWorkspaceBoundary } from '../src/mcp/workspace-boundary.js';

const temporaryRoots: string[] = [];

async function fixture(): Promise<{
  root: string;
  allowed: string;
  nested: string;
  outside: string;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-mcp-'));
  temporaryRoots.push(root);

  const allowed = path.join(root, 'allowed');
  const nested = path.join(allowed, 'nested');
  const outside = path.join(root, 'outside');

  await Promise.all([
    mkdir(nested, { recursive: true }),
    mkdir(outside, { recursive: true })
  ]);

  return { root, allowed, nested, outside };
}

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) =>
      rm(root, { recursive: true, force: true })
    )
  );
});

describe('MCP workspace boundary', () => {
  it('allows the approved root and real nested paths', async () => {
    const { allowed, nested } = await fixture();
    const boundary = await createWorkspaceBoundary([allowed]);

    await expect(boundary.resolve(allowed)).resolves.toBe(
      await realpath(allowed)
    );
    await expect(boundary.resolve(nested)).resolves.toBe(
      await realpath(nested)
    );
  });

  it('denies sibling paths and traversal outside the workspace', async () => {
    const { allowed, outside } = await fixture();
    const boundary = await createWorkspaceBoundary([allowed]);

    await expect(boundary.resolve(outside)).rejects.toMatchObject({
      code: 'MCP_WORKSPACE_DENIED'
    });
    await expect(
      boundary.resolve(path.join(allowed, '..', path.basename(outside)))
    ).rejects.toMatchObject({ code: 'MCP_WORKSPACE_DENIED' });
  });

  it('denies symlinks that resolve outside the approved workspace', async () => {
    const { allowed, outside } = await fixture();
    const link = path.join(allowed, 'escape');
    await symlink(outside, link, process.platform === 'win32' ? 'junction' : 'dir');

    const boundary = await createWorkspaceBoundary([allowed]);

    await expect(boundary.resolve(link)).rejects.toMatchObject({
      code: 'MCP_WORKSPACE_DENIED'
    });
  });

  it('fails closed for paths that cannot be resolved', async () => {
    const { allowed } = await fixture();
    const boundary = await createWorkspaceBoundary([allowed]);

    await expect(
      boundary.resolve(path.join(allowed, 'missing'))
    ).rejects.toMatchObject({
      code: 'MCP_WORKSPACE_UNRESOLVABLE'
    });
  });
});
