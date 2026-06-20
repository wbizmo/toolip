import { describe, expect, it } from 'vitest';
import { calculateDependencyHealth, calculateScore, gradeScore } from '../src/core/score.js';

describe('score', () => {
  it('calculates default perfect score', () => {
    const score = calculateScore();

    expect(score.overall).toBe(100);
    expect(score.grade).toBe('A');
  });

  it('calculates weighted score average', () => {
    const score = calculateScore({
      dependencyHealth: 90,
      secretHygiene: 80,
      configurationSecurity: 70,
      gitSafety: 60
    });

    expect(score.overall).toBe(75);
    expect(score.grade).toBe('C');
  });

  it('grades scores', () => {
    expect(gradeScore(95)).toBe('A');
    expect(gradeScore(85)).toBe('B');
    expect(gradeScore(75)).toBe('C');
    expect(gradeScore(65)).toBe('D');
    expect(gradeScore(30)).toBe('F');
  });

  it('calculates dependency health from findings', () => {
    const health = calculateDependencyHealth([
      {
        id: 'A',
        title: 'A',
        severity: 'high',
        category: 'supply-chain',
        message: 'A',
        recommendation: 'A'
      },
      {
        id: 'B',
        title: 'B',
        severity: 'medium',
        category: 'supply-chain',
        message: 'B',
        recommendation: 'B'
      }
    ]);

    expect(health).toBe(63);
  });
});
