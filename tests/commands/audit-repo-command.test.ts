import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('audit-repo command', () => {
  it('is registered', async () => {
    const source = await readFile('src/index.ts', 'utf8');
    expect(source).toContain('registerAuditRepoCommand(program);');
  });
});
