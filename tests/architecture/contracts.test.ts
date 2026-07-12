import { describe, expect, it } from 'vitest';
import { AnalyzerRunner } from '../../src/application/analyzer-runner.js';
import type { Analyzer } from '../../src/contracts/analyzer.js';
import { assertValidRuleId } from '../../src/contracts/rule.js';
import { MemoryCache } from '../../src/storage/memory-cache.js';

describe('v2 architecture contracts', () => {
  it('validates stable Toolip rule identifiers', () => {
    expect(() => assertValidRuleId('TLP-SEC-001')).not.toThrow();
    expect(() => assertValidRuleId('security-1')).toThrow();
  });

  it('stores and retrieves cached analyzer data', async () => {
    const cache = new MemoryCache();

    await cache.set('package:express', { version: '5.0.0' });

    await expect(
      cache.get<{ version: string }>('package:express')
    ).resolves.toEqual({ version: '5.0.0' });
  });

  it('runs analyzers through the shared runner', async () => {
    const analyzer: Analyzer = {
      id: 'test-analyzer',
      version: '1.0.0',
      async analyze() {
        return {
          analyzer: 'test-analyzer',
          durationMs: 0,
          findings: []
        };
      }
    };

    const runner = new AnalyzerRunner({
      concurrency: 2,
      timeoutMs: 5_000
    });

    const results = await runner.run([analyzer], {
      root: process.cwd()
    });

    expect(results).toHaveLength(1);
    expect(results[0]?.analyzer).toBe('test-analyzer');
  });
});
