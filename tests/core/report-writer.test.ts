import { describe, expect, it } from 'vitest';
import {
  serializeJsonOutputBounded,
  serializeJsonOutputWithinBudget
} from '../../src/core/report-writer.js';

describe('bounded report serialization', () => {
  it('preserves ordinary JSON values and property order', () => {
    expect(
      serializeJsonOutputBounded({
        findings: [{ id: 'TLP-1', score: 0, tags: ['safe'] }]
      })
    ).toBe('{"findings":[{"id":"TLP-1","score":0,"tags":["safe"]}]}');
    expect(serializeJsonOutputBounded({ control: '\u000b' })).toBe(
      '{"control":"\\u000b"}'
    );
  });

  it('fails before allocating an oversized escaped report string', () => {
    expect(() =>
      serializeJsonOutputBounded('\n'.repeat(33 * 1024 * 1024))
    ).toThrow('JSON output exceeds its configured budget.');
  });

  it('enforces a smaller artifact-specific output ceiling', () => {
    expect(serializeJsonOutputWithinBudget({ value: 'ok' }, 14)).toBe(
      '{"value":"ok"}'
    );
    expect(() =>
      serializeJsonOutputWithinBudget({ value: 'too large' }, 14)
    ).toThrow('JSON output exceeds its configured budget.');
  });

  it('preserves UTF-8 bytes across bounded string chunks', () => {
    const value = `${'x'.repeat(65_535)}😀`;
    const serialized = serializeJsonOutputWithinBudget(value, 65_541);
    expect(Buffer.byteLength(serialized, 'utf8')).toBe(65_541);
    expect(JSON.parse(serialized)).toBe(value);
  });

  it('rejects cycles and excessive nesting explicitly', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => serializeJsonOutputBounded(cyclic)).toThrow(
      'JSON output contains a cycle.'
    );

    let deep: unknown = 'leaf';
    for (let index = 0; index < 300; index += 1) deep = { child: deep };
    expect(() => serializeJsonOutputBounded(deep)).toThrow(
      'JSON output exceeds its traversal budget.'
    );
  });
});
