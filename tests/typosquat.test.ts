import { describe, expect, it } from 'vitest';
import { detectTyposquat } from '../src/core/typosquat.js';

describe('detectTyposquat', () => {
  it('suggests likely intended packages', () => {
    const result = detectTyposquat('expres');

    expect(result.suspected).toBe(true);
    expect(result.suggestions).toContain('express');
  });

  it('does not flag exact package names', () => {
    const result = detectTyposquat('express');

    expect(result.suspected).toBe(false);
  });
});
