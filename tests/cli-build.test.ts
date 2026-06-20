import { describe, expect, it } from 'vitest';
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

describe('CLI build configuration', () => {
  it('has a publishable CLI bin entry', async () => {
    const raw = await readFile(path.join(process.cwd(), 'package.json'), 'utf8');
    const pkg = JSON.parse(raw) as {
      name: string;
      bin: Record<string, string>;
      license: string;
      author: string;
    };

    expect(pkg.name).toBe('toolip');
    expect(pkg.bin.toolip).toBe('./dist/src/index.js');
    expect(pkg.license).toBe('MIT');
    expect(pkg.author).toContain('Ashibuogwu Williams');
  });

  it('has the expected source entry after build', async () => {
    expect(await exists(path.join(process.cwd(), 'src', 'index.ts'))).toBe(true);
  });
});
