import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { afterEach, describe, expect, it } from 'vitest';

const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0)) await fn();
});

async function connect(root: string) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['--import', 'tsx', 'src/index.ts', 'mcp', '--allow-root', root],
    stderr: 'pipe'
  });
  const client = new Client({ name: 'toolip-smoke', version: '0.0.0' });
  await client.connect(transport);
  cleanup.push(() => client.close());
  return client;
}

describe('MCP stdio server (issue #50)', () => {
  it('lists tools and enforces the approved workspace boundary', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-mcp-'));
    cleanup.push(() => rm(root, { recursive: true, force: true }));
    const outside = await mkdtemp(path.join(os.tmpdir(), 'toolip-mcp-out-'));
    cleanup.push(() => rm(outside, { recursive: true, force: true }));

    const client = await connect(root);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'toolip_diff',
      'toolip_doctor',
      'toolip_sbom'
    ]);

    const allowed = await client.callTool({
      name: 'toolip_doctor',
      arguments: { root }
    });
    expect(allowed.isError).not.toBe(true);

    const denied = await client
      .callTool({ name: 'toolip_doctor', arguments: { root: outside } })
      .then(
        (r) => r,
        (e: unknown) => ({ isError: true, thrown: String(e) })
      );
    expect(denied.isError).toBe(true);
  }, 60_000);

  it('rejects malformed tool input without crashing the server', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-mcp-'));
    cleanup.push(() => rm(root, { recursive: true, force: true }));
    const client = await connect(root);

    const bad = await client
      .callTool({ name: 'toolip_sbom', arguments: { root, format: 'bogus' } })
      .then(
        (r) => r,
        (e: unknown) => ({ isError: true, thrown: String(e) })
      );
    expect(bad.isError).toBe(true);

    const still = await client.listTools();
    expect(still.tools.length).toBe(3);
  }, 60_000);
});
