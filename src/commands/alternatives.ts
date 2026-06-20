import type { Command } from 'commander';
import chalk from 'chalk';
import { findAlternatives } from '../core/alternatives.js';

export function registerAlternativesCommand(program: Command): void {
  program
    .command('alternatives <package>')
    .description('Suggest safer or better-maintained package alternatives.')
    .action((packageName: string) => {
      const result = findAlternatives(packageName);

      console.log(chalk.bold(`Alternatives for ${result.package}`));
      console.log('');

      for (const alternative of result.alternatives) {
        console.log(`${chalk.green('✓')} ${chalk.bold(alternative.name)}`);
        console.log(`  ${alternative.reason}`);
      }
    });
}
