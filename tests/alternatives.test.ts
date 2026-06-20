import { describe, expect, it } from 'vitest';
import { findAlternatives } from '../src/core/alternatives.js';

describe('findAlternatives', () => {
  it('returns curated alternatives for request', () => {
    const result = findAlternatives('request');

    expect(result.alternatives.map((item) => item.name)).toContain('got');
    expect(result.alternatives.map((item) => item.name)).toContain('undici');
  });

  it('returns fallback guidance for unknown packages', () => {
    const result = findAlternatives('some-random-package');

    expect(result.alternatives[0]?.name).toBe('No curated alternative yet');
  });
});
