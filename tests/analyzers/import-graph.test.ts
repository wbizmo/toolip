import { describe, expect, it } from 'vitest';
import { extractPackageImports } from '../../src/analyzers/reachability/import-graph.js';

describe('package import extraction', () => {
  it('captures runtime imports, re-exports, CommonJS forms and unresolved loaders', () => {
    const references = extractPackageImports(
      'entry.ts',
      `import type { Shape } from 'types-only';
import { type Shape as Alias, create } from 'mixed-package';
export { run } from 're-exported';
import legacy = require('legacy-package');
require(process.env.PACKAGE_NAME);
import(process.env.DYNAMIC_MODULE);
void Shape; void Alias; void create; void legacy;
`
    );

    expect(
      references.map(({ packageName, kind }) => [packageName, kind])
    ).toEqual([
      ['mixed-package', 'named'],
      ['re-exported', 're-export'],
      ['legacy-package', 'require'],
      ['*', 'dynamic-require'],
      ['*', 'dynamic-import']
    ]);
    expect(references[0]?.importedSymbols).toEqual(['create']);
  });

  it('captures literal dynamic imports while ignoring type-only re-exports', () => {
    const references = extractPackageImports(
      'entry.ts',
      `import('literal-package', { with: { type: 'json' } });
export type { Shape } from 'types-only';
`
    );

    expect(references).toMatchObject([
      {
        packageName: 'literal-package',
        kind: 'dynamic-import',
        specifier: 'literal-package'
      }
    ]);
  });
});
