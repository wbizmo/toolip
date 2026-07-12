import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('docker-scan command', () => {
  it('is registered', async () => {
    const source = await readFile('src/index.ts', 'utf8');
    expect(source).toContain('registerDockerScanCommand(program);');
  });
});
