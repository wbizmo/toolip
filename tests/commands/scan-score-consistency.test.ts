import {
  readFile
} from 'node:fs/promises';
import {
  describe,
  expect,
  it
} from 'vitest';

describe('scan and score consistency', () => {
  it('uses the canonical dependency-health result in both commands', async () => {
    const scanSource = await readFile(
      'src/commands/scan.ts',
      'utf8'
    );

    const scoreSource = await readFile(
      'src/commands/score.ts',
      'utf8'
    );

    expect(scanSource).toContain(
      'dependencyScan.dependencyHealth'
    );

    expect(scoreSource).toContain(
      'dependencyScan.dependencyHealth'
    );

    expect(scanSource).not.toContain(
      'calculateDependencyHealth('
    );

    expect(scoreSource).not.toContain(
      'calculateDependencyHealthFromPackages('
    );
  });

  it('calculates dependency health once in the dependency scanner', async () => {
    const source = await readFile(
      'src/core/dependency-scan.ts',
      'utf8'
    );

    expect(source).toContain(
      'calculateDependencyHealthFromPackages'
    );

    expect(source).toContain(
      'dependencyHealth,'
    );
  });
});
