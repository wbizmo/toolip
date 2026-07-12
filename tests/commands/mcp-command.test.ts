import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('mcp command', () => {
  it('is registered', async () => {
    const source = await readFile('src/index.ts', 'utf8');
    expect(source).toContain('registerMcpCommand(program);');
  });

  it('ships the MCP SDK as a runtime dependency', async () => {
    const pkg = JSON.parse(await readFile('package.json', 'utf8')) as {
      dependencies?: Record<string, string>;
    };

    expect(pkg.dependencies?.['@modelcontextprotocol/sdk']).toBeDefined();
  });
});
