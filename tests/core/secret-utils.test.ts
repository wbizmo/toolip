import { describe, expect, it } from 'vitest';
import {
  findSecretMatches,
  lineAndColumn
} from '../../src/core/secret-utils.js';
import { scanConfigurationContent } from '../../src/core/security-doctor.js';

describe('secret source locations', () => {
  it('maps repeated matches and source offsets to one-based line positions', () => {
    const content = 'first\nTOKEN here\nthird\nTOKEN';

    expect(
      findSecretMatches(content, /TOKEN/).map(({ line, column }) => ({
        line,
        column
      }))
    ).toEqual([
      { line: 2, column: 1 },
      { line: 4, column: 1 }
    ]);
    expect(lineAndColumn(content, content.indexOf('third'))).toEqual({
      line: 3,
      column: 1
    });
  });

  it('does not inherit a caller regex lastIndex and handles a large match set', () => {
    const content = Array.from({ length: 5_000 }, (_, index) =>
      index % 5 === 0 ? `TOKEN-${index}\n` : `line-${index}\n`
    ).join('');
    const pattern = /TOKEN-\d+/g;
    pattern.lastIndex = content.length;

    const matches = findSecretMatches(content, pattern);

    expect(matches).toHaveLength(1_000);
    expect(matches[0]).toMatchObject({ line: 1, column: 1 });
    expect(matches.at(-1)).toMatchObject({ line: 4_996, column: 1 });
    expect(pattern.lastIndex).toBe(content.length);
  });

  it('keeps location work bounded for 50,000 matches in a maximum-size source', () => {
    const repeatedMatches = 'TOKEN\n'.repeat(50_000);
    const content =
      repeatedMatches + 'x'.repeat(2 * 1024 * 1024 - repeatedMatches.length);

    const matches = findSecretMatches(content, /TOKEN/g);

    expect(content.length).toBe(2 * 1024 * 1024);
    expect(matches).toHaveLength(50_000);
    expect(matches[0]).toMatchObject({ index: 0, line: 1, column: 1 });
    expect(matches[24_999]).toMatchObject({
      index: 24_999 * 6,
      line: 25_000,
      column: 1
    });
    expect(matches.at(-1)).toMatchObject({
      index: 49_999 * 6,
      line: 50_000,
      column: 1
    });
  });

  it('maps many configuration matches without rescanning each source prefix', () => {
    const content = Array.from(
      { length: 2_000 },
      () => 'const cfg = { origin: "*" };\n'
    ).join('');
    const findings = scanConfigurationContent('config.ts', content);
    expect(findings).toHaveLength(2_000);
    expect(findings[0]?.location).toMatchObject({ line: 1 });
    expect(findings.at(-1)?.location).toMatchObject({ line: 2_000 });
  });
});
