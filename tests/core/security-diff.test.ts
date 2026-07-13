import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';

describe('security diff', () => {
  it('ships the diff command implementation', async () => {
    const source = await readFile('src/commands/diff.ts', 'utf8');
    expect(source).toContain("command('diff <base> [head]')");
  });
});
