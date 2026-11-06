import { afterEach, describe, expect, it, vi } from 'vitest';
import { ToolipError } from '../src/errors/toolip-error.js';
import { handleError } from '../src/utils/error-handler.js';

describe('CLI error sanitization', () => {
  afterEach(() => vi.restoreAllMocks());

  it('redacts unquoted passphrase and passwd assignments in generic errors', () => {
    const output = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`exit:${code}`);
    });

    expect(() =>
      handleError(
        new Error('unlock failed: passphrase=first-secret passwd=second-secret')
      )
    ).toThrow('exit:1');

    const rendered = output.mock.calls.flat().join(' ');
    expect(rendered).toContain('passphrase=[redacted]');
    expect(rendered).toContain('passwd=[redacted]');
    expect(rendered).not.toContain('first-secret');
    expect(rendered).not.toContain('second-secret');
  });

  it('redacts unquoted assignments in typed Toolip errors', () => {
    const output = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`exit:${code}`);
    });

    expect(() =>
      handleError(
        new ToolipError('vault unlock failed: passphrase=typed-secret', {
          code: 'VAULT_ERROR',
          exitCode: 3
        })
      )
    ).toThrow('exit:3');

    const rendered = output.mock.calls.flat().join(' ');
    expect(rendered).toContain('passphrase=[redacted]');
    expect(rendered).not.toContain('typed-secret');
  });
});
