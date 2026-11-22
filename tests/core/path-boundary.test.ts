import { describe, expect, it } from 'vitest';
import { isWithinPath } from '../../src/core/path-boundary.js';

describe('isWithinPath', () => {
  it('treats Windows long-path prefixes as equivalent to drive paths', () => {
    expect(
      isWithinPath(
        String.raw`\\?\C:\Users\runner\project`,
        String.raw`c:\users\RUNNER\project\node_modules\pkg`,
        'win32'
      )
    ).toBe(true);
    expect(
      isWithinPath(
        String.raw`\\?\C:\Users\runner\project`,
        String.raw`C:\Users\runner\project-sibling\pkg`,
        'win32'
      )
    ).toBe(false);
  });

  it('normalizes extended UNC paths without widening the share boundary', () => {
    expect(
      isWithinPath(
        String.raw`\\?\UNC\server\share\project`,
        String.raw`\\server\share\project\node_modules\pkg`,
        'win32'
      )
    ).toBe(true);
    expect(
      isWithinPath(
        String.raw`\\?\UNC\server\share\project`,
        String.raw`\\server\share-other\project\pkg`,
        'win32'
      )
    ).toBe(false);
  });
});
