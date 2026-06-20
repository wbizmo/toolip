import type { Command } from 'commander';
import chalk from 'chalk';
import { analyzePackage } from '../core/analyze-package.js';

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

      console.log(chalk.bold(`Package: ${result.name}`));
      console.log('');

      console.log(`Latest Version: ${result.latestVersion}`);
      console.log(`Deprecated: ${result.deprecated}`);
      console.log(`Maintainers: ${result.maintainers}`);
      console.log(`Risk Score: ${result.riskScore}`);
      console.log(`Published: ${result.publishedAt}`);
    });
}
