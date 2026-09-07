import { describe, expect, it } from 'vitest';
import {
  calculateScore,
  measuredDimension,
  unmeasuredDimension
} from '../../src/core/score.js';

describe('scan and score consistency', () => {
  it('uses one measurement-aware score contract for complete results', () => {
    const score = calculateScore({
      dependencyHealth: measuredDimension(80),
      secretHygiene: measuredDimension(90),
      configurationSecurity: measuredDimension(100),
      gitSafety: measuredDimension(70)
    });

    expect(score.complete).toBe(true);
    expect(score.overall).toBe(85);
    expect(score.grade).toBe('B');
  });

  it('cannot create an optimistic aggregate from partial analysis', () => {
    const score = calculateScore({
      dependencyHealth: measuredDimension(100),
      secretHygiene: measuredDimension(100),
      configurationSecurity: unmeasuredDimension(
        'failed',
        'configuration analyzer failed'
      ),
      gitSafety: measuredDimension(100)
    });

    expect(score.configurationSecurity).toBeNull();
    expect(score.overall).toBeNull();
    expect(score.grade).toBeNull();
    expect(score.complete).toBe(false);
  });
});
