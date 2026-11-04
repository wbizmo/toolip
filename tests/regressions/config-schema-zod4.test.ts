import { describe, expect, it } from 'vitest';
import { toolipConfigSchema } from '../../src/core/config/schema.js';

// Regression: zod 4 requires an explicit key schema for z.record(); the
// upgrade to zod >= 4.6.6 (GHSA-mrhx-c7xc-m3w5) must keep config parsing typed.
describe('config schema under zod 4', () => {
  it('applies defaults to an empty config', () => {
    const config = toolipConfigSchema.parse({});
    expect(config.rules).toEqual({});
    expect(config.history.maxEntries).toBe(500);
    expect(config.providers.osv.timeoutMs).toBe(20000);
  });

  it('parses per-rule overrides keyed by rule id', () => {
    const config = toolipConfigSchema.parse({
      rules: {
        'secret.generic': {
          severity: 'low',
          paths: [{ pattern: 'tests/**', enabled: false }]
        }
      }
    });
    expect(config.rules['secret.generic']?.severity).toBe('low');
    expect(config.rules['secret.generic']?.paths?.[0]?.pattern).toBe(
      'tests/**'
    );
  });

  it('rejects invalid severities and short suppression reasons', () => {
    expect(
      toolipConfigSchema.safeParse({ rules: { r: { severity: 'urgent' } } })
        .success
    ).toBe(false);
    expect(
      toolipConfigSchema.safeParse({
        suppressions: [{ ruleId: 'r', reason: 'x' }]
      }).success
    ).toBe(false);
  });
});
