import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

describe('AST scan command registration', () => {
  it('registers ast-scan in the CLI', async () => {
    const source = await readFile(
      path.join(process.cwd(), 'src', 'index.ts'),
      'utf8'
    );

    expect(source).toContain(
      'registerAstScanCommand(program);'
    );
  });

  it('ships TypeScript as a runtime dependency', async () => {
    const pkg = JSON.parse(
      await readFile(
        path.join(process.cwd(), 'package.json'),
        'utf8'
      )
    ) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };

    expect(pkg.dependencies?.typescript).toBeDefined();
    expect(
      pkg.devDependencies?.typescript
    ).toBeUndefined();
  });
});
