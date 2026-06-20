import type { Command } from 'commander';
import { comparePackages } from '../core/compare-packages.js';
import { printPackageComparison } from '../utils/package-output.js';
import { ToolipError } from '../errors/toolip-error.js';

export function registerCompareCommand(program: Command): void {
  program
    .command('compare <packages...>')
    .description('Compare npm packages by maintenance and risk signals.')
    .action(async (packageNames: string[]) => {
      if (packageNames.length < 2) {
        throw new ToolipError('Please provide at least two packages to compare.', {
          code: 'COMPARE_REQUIRES_TWO_PACKAGES',
          exitCode: 1
        });
      }

      const comparison = await comparePackages(packageNames);
      printPackageComparison(comparison);
    });
}
