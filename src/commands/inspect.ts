import type { Command } from 'commander';
import { analyzePackage } from '../core/analyze-package.js';
import { printPackageHealth } from '../utils/package-output.js';

export function registerInspectCommand(program: Command): void {
  program
    .command('inspect <package>')
    .description('Inspect a package from npm registry.')
    .action(async (packageName: string) => {
      const result = await analyzePackage({
        name: packageName,
        version: 'latest',
        type: 'dependency'
      });

      printPackageHealth(result);
    });
}
