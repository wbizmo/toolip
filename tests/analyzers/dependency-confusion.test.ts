import {
  mkdtemp,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DependencyConfusionAnalyzer } from '../../src/analyzers/dependency-confusion/analyzer.js';

describe('DependencyConfusionAnalyzer', () => {
  it('flags internal package names that exist publicly', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-confusion-')
    );

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            '@company/internal-utils': 'workspace:*'
          }
        })
      );

      const analyzer = new DependencyConfusionAnalyzer(
        async () => true
      );

      const result = await analyzer.analyze({ root });

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.ruleId).toBe('TLP-CONFUSION-001');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('runs independent registry lookups concurrently within the configured bound', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-confusion-')
    );
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

      const analyzer = new DependencyConfusionAnalyzer(
        async () => {
          active += 1;
          peak = Math.max(peak, active);
          await new Promise((resolve) => setTimeout(resolve, 10));
          active -= 1;
          return false;
        },
        2
      );

      const result = await analyzer.analyze({ root });

      expect(peak).toBe(2);
      expect(result.findings).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
