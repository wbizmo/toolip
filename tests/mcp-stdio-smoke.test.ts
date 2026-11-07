import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
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
      'toolip_policy_check',
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
    expect(still.tools.length).toBe(4);
  }, 60_000);

  it('evaluates versioned policy from the same bounded snapshot with offline defaults', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-mcp-policy-'));
    cleanup.push(() => rm(root, { recursive: true, force: true }));
    await mkdir(path.join(root, '.toolip'));
    await writeFile(
      path.join(root, '.toolip/policy.yaml'),
      'version: 1\nminimumSeverity: high\nminimumCoverage: 1\n'
    );
    await writeFile(
      path.join(root, 'package.json'),
      '{"name":"mcp-policy-fixture","version":"1.0.0"}\n'
    );
    await writeFile(path.join(root, '.gitignore'), '.env\n.env.*\n');
    execFileSync('git', ['init', '-q'], { cwd: root });
    execFileSync('git', ['config', 'user.name', 'Toolip Test'], { cwd: root });
    execFileSync('git', ['config', 'user.email', 'toolip@example.test'], {
      cwd: root
    });
    execFileSync('git', ['add', '.'], { cwd: root });
    execFileSync('git', ['commit', '-qm', 'policy fixture'], { cwd: root });
    const client = await connect(root);
    const result = (await client.callTool({
      name: 'toolip_policy_check',
      arguments: { root, policyFile: '.toolip/policy.yaml' }
    })) as { isError?: boolean; content: Array<{ text: string }> };

    expect(result.isError).not.toBe(true);
    const output = JSON.parse(result.content[0]?.text ?? '{}');
    expect(output).toMatchObject({
      decision: 'pass',
      policy: { version: 1, trusted: false },
      analysis: { state: 'complete' }
    });
  }, 60_000);

  it('returns structured errors for hostile Git revisions and writes nothing (issue #45)', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-mcp-'));
    cleanup.push(() => rm(root, { recursive: true, force: true }));
    const canary = path.join(root, 'canary.txt');
    const client = await connect(root);

    const result = (await client.callTool({
      name: 'toolip_diff',
      arguments: { root, base: `--output=${canary}`, head: 'HEAD' }
    })) as { isError?: boolean; content: Array<{ text: string }> };

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0]?.text ?? '{}');
    expect(body.error.code).toBe('GIT_REVISION_INVALID');
    expect(JSON.stringify(body)).not.toContain(root);
    expect(existsSync(canary)).toBe(false);
  }, 60_000);
});
