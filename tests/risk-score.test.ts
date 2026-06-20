import { describe, expect, it } from 'vitest';
import { calculateRiskScore } from '../src/core/risk-score.js';

describe('risk scoring', () => {
  it('increases risk for deprecated packages', () => {
    const score = calculateRiskScore({
      deprecated: true,
      maintainers: 1,
      ageInDays: 900
    });

    expect(score).toBeGreaterThan(40);
  });
});
