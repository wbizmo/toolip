import { describe, expect, it } from 'vitest';
import { generateAnnouncement } from '../../src/core/announce/generate.js';

describe('announcement generation', () => {
  it('generates deterministic text', () => {
    const result = generateAnnouncement({
      version: '2.0.0',
      fixed: 2,
      added: 1,
      removed: 0,
      scoreBefore: 82,
      scoreAfter: 91
    });

    expect(result).toContain('Toolip 2.0.0 security update');
    expect(result).toContain('Security score: 82 → 91');
  });
});
