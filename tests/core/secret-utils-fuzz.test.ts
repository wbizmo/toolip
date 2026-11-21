import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  createLineLocator,
  findSecretMatches
} from '../../src/core/secret-utils.js';

function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

describe('deterministic secret-location fuzz corpus', () => {
  it('matches a straightforward reference for randomized newline and Unicode inputs', () => {
    const next = random(0x5ec7e7);
    const alphabet = ['a', 'Z', '0', '\n', '\r', '\t', ' ', '😀', 'é'];
    const pattern = /TOK[A-Z]{2}/gu;

    for (let caseIndex = 0; caseIndex < 500; caseIndex += 1) {
      const length = next() % 2_000;
      const content = Array.from(
        { length },
        () => alphabet[next() % alphabet.length] ?? 'x'
      ).join('');
      const expressions: Array<{ index: number; value: string }> = [];
      const count = next() % 20;
      for (let matchIndex = 0; matchIndex < count; matchIndex += 1) {
        const value = `TOK${String.fromCharCode(65 + (next() % 26))}${String.fromCharCode(65 + (next() % 26))}`;
        const index = next() % (content.length + 1);
        expressions.push({ index, value });
      }
      const source =
        expressions.length === 0
          ? content
          : insertMatches(content, expressions);
      const locator = createLineLocator(source);
      const actual = findSecretMatches(source, pattern).map((match) => ({
        value: match.value,
        index: match.index,
        line: match.line,
        column: match.column,
        fingerprint: match.fingerprint
      }));
      const expected: typeof actual = [];
      const referencePattern = /TOK[A-Z]{2}/gu;
      for (const match of source.matchAll(referencePattern)) {
        const value = match[0];
        const index = match.index ?? 0;
        const before = source.slice(0, index);
        const lastNewline = before.lastIndexOf('\n');
        expected.push({
          value,
          index,
          line: before.split('\n').length,
          column: index - lastNewline,
          fingerprint: createHash('sha256').update(value).digest('hex')
        });
      }
      expect(actual, `deterministic fuzz case ${caseIndex}`).toEqual(expected);

      const positions = new Set([0, source.length]);
      for (let sample = 0; sample < 8; sample += 1)
        positions.add(next() % (source.length + 1));
      for (const index of positions) {
        const before = source.slice(0, index);
        const lastNewline = before.lastIndexOf('\n');
        expect(locator(index)).toEqual({
          line: before.split('\n').length,
          column: index - lastNewline
        });
      }
    }
  });
});

function insertMatches(
  content: string,
  expressions: readonly { index: number; value: string }[]
): string {
  const sorted = [...expressions].sort(
    (left, right) => right.index - left.index
  );
  let result = content;
  for (const expression of sorted) {
    result =
      result.slice(0, expression.index) +
      expression.value +
      result.slice(expression.index);
  }
  return result;
}
