import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DependencyConfusionAnalyzer } from '../../src/analyzers/dependency-confusion/analyzer.js';

describe('DependencyConfusionAnalyzer', () => {
  it('flags internal package names that exist publicly', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-confusion-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            '@company/internal-utils': 'workspace:*'
          }
        })
      );

      const analyzer = new DependencyConfusionAnalyzer(async () => true);

      const result = await analyzer.analyze({ root });

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.ruleId).toBe('TLP-CONFUSION-001');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('runs independent registry lookups concurrently within the configured bound', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-confusion-'));
    let active = 0;
    let peak = 0;

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: Object.fromEntries(
            Array.from({ length: 6 }, (_, index) => [
              `@company/internal-${index}`,
              'workspace:*'
            ])
          )
        })
      );

      const analyzer = new DependencyConfusionAnalyzer(async () => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 10));
        active -= 1;
        return false;
      }, 2);

      const result = await analyzer.analyze({ root });

      expect(peak).toBe(2);
      expect(result.findings).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('reports partial coverage when the bounded registry lookup count is reached', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-confusion-'));
    let lookups = 0;

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: Object.fromEntries(
            Array.from({ length: 5_001 }, (_, index) => [
              `@company/internal-${index}`,
              'workspace:*'
            ])
          )
        })
      );

      const result = await new DependencyConfusionAnalyzer(async () => {
        lookups += 1;
        return false;
      }).analyze({ root });

      expect(lookups).toBe(5_000);
      expect(result.coverage).toMatchObject({
        state: 'partial',
        eligible: 5_001,
        scanned: 5_000,
        skipped: 1,
        failed: 0
      });
      expect(result.warnings).toContain(
        'Dependency confusion lookup budget or input limits withheld 1 candidate(s).'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('fails closed on a package manifest above the bounded read size', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-confusion-'));
    let lookups = 0;

    try {
      await writeFile(
        path.join(root, 'package.json'),
        ' '.repeat(2 * 1024 * 1024 + 1)
      );

      const result = await new DependencyConfusionAnalyzer(async () => {
        lookups += 1;
        return true;
      }).analyze({ root });

      expect(lookups).toBe(0);
      expect(result.coverage).toMatchObject({
        state: 'failed',
        eligible: 1,
        scanned: 0,
        skipped: 1
      });
      expect(result.warnings).toContain(
        'package.json exceeds the 2 MiB analysis limit'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not send oversized package identities to the registry', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-confusion-'));
    let lookups = 0;
    try {
      const oversizedName = `@${'a'.repeat(214)}`;
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({ dependencies: { [oversizedName]: 'workspace:*' } })
      );

      const result = await new DependencyConfusionAnalyzer(async () => {
        lookups += 1;
        return true;
      }).analyze({ root });

      expect(lookups).toBe(0);
      expect(result.coverage.state).toBe('failed');
      expect(result.metadata).toMatchObject({
        candidates: 1,
        checkedCandidates: 0,
        rejectedCandidates: 1
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
