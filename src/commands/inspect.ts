import type { Command } from 'commander';
import chalk from 'chalk';
import { analyzePackage } from '../core/analyze-package.js';
import { detectTyposquat } from '../core/typosquat.js';
import { printPackageHealth } from '../utils/package-output.js';

export function registerInspectCommand(program: Command): void {
  program
    .command('inspect <package>')
    .description('Inspect a package from npm registry.')
    .action(async (packageName: string) => {
      const typo = detectTyposquat(packageName);

      if (typo.suspected) {
        console.log(chalk.yellow('Potential typosquatting signal detected.'));
        console.log(`Did you mean: ${typo.suggestions.join(', ')}`);
        console.log('');
      }

      const result = await analyzePackage({
        name: packageName,
        version: 'latest',
        type: 'dependency'
      });

      printPackageHealth(result);
    });
}
