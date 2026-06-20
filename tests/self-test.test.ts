import { describe, expect, it } from 'vitest';
import { TOOLIP_AUTHOR, TOOLIP_VERSION } from '../src/config/version.js';
import { ToolipError } from '../src/errors/toolip-error.js';

describe('version config', () => {
  it('exposes Toolip version and author metadata', () => {
    expect(TOOLIP_VERSION).toBe('0.1.0');
    expect(TOOLIP_AUTHOR.name).toBe('Ashibuogwu Williams');
    expect(TOOLIP_AUTHOR.handle).toBe('wbizmo');
  });
});

describe('ToolipError', () => {
  it('stores code and exit code', () => {
    const error = new ToolipError('Broken', {
      code: 'BROKEN',
      exitCode: 2
    });

    expect(error.message).toBe('Broken');
    expect(error.code).toBe('BROKEN');
    expect(error.exitCode).toBe(2);
  });
});
