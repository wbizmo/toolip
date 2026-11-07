import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../../src/core/canonical-json.js';

describe('canonical JSON evidence serialization', () => {
  it('orders integer-shaped keys lexically and retains prototype-named data', () => {
    const value = JSON.parse(
      '{"2":"two","10":"ten","__proto__":{"safe":true}}'
    ) as Record<string, unknown>;

    expect(canonicalJson(value)).toBe(
      '{"10":"ten","2":"two","__proto__":{"safe":true}}'
    );
  });

  it('rejects accessors without invoking them and rejects sparse arrays', () => {
    let getterCalls = 0;
    const value = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(value, 'evidence', {
      enumerable: true,
      get() {
        getterCalls++;
        return 'must not execute';
      }
    });

    expect(() => canonicalJson(value)).toThrow(/data values/u);
    expect(getterCalls).toBe(0);
    const sparse = new Array(2);
    sparse[1] = 'value';
    expect(() => canonicalJson(sparse)).toThrow(/data values/u);
  });

  it('detects cycles through arrays and rejects non-JSON prototypes', () => {
    const cyclic: unknown[] = [];
    cyclic.push(cyclic);
    expect(() => canonicalJson(cyclic)).toThrow(/cyclic/u);
    expect(() => canonicalJson(new Date(0))).toThrow(/plain objects/u);
  });

  it('bounds nesting and rejects unsupported numeric values', () => {
    let nested: unknown = 'leaf';
    for (let depth = 0; depth < 258; depth++) nested = [nested];
    expect(() => canonicalJson(nested)).toThrow(/nesting budget/u);
    expect(() => canonicalJson({ confidence: Number.NaN })).toThrow(
      /non-finite/u
    );
  });
});
