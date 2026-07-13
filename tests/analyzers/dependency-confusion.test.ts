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
      path.join(
        os.tmpdir(),
        'toolip-confusion-'
      )
    );

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            '@company/internal-utils':
              'workspace:*'
          }
        })
      );

      const analyzer =
        new DependencyConfusionAnalyzer(
          async () => true
        );

      const result = await analyzer.analyze({
        root
      });

      expect(result.findings).toHaveLength(1);
      expect(
        result.findings[0]?.ruleId
      ).toBe('TLP-CONFUSION-001');
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });
});
