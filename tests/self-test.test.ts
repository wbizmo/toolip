import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  TOOLIP_AUTHOR,
  TOOLIP_VERSION
} from '../src/config/version.js';
import { ToolipError } from '../src/errors/toolip-error.js';

describe('version config', () => {
  it('uses package.json as the version source of truth', async () => {
    const raw = await readFile(
      path.join(process.cwd(), 'package.json'),
      'utf8'
    );

    const pkg = JSON.parse(raw) as {
      version: string;
    };

    expect(TOOLIP_VERSION).toBe(pkg.version);
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
