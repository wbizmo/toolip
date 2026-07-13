import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

describe('sbom command', () => {
  it('is registered in the CLI', async () => {
    const source = await readFile(
      path.join(process.cwd(), 'src', 'index.ts'),
      'utf8'
    );

    expect(source).toContain(
      'registerSbomCommand(program);'
    );
  });
});
