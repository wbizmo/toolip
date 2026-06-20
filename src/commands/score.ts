import type { Command } from 'commander';
import chalk from 'chalk';
import { scanDependencies } from '../core/dependency-scan.js';
import { calculateDependencyHealth, calculateScore } from '../core/score.js';

export function registerScoreCommand(program: Command): void {
  program
    .command('score')
    .description('Calculate a Toolip security scorecard for the current project.')
    .option('-p, --path <path>', 'Project path to score.', process.cwd())
    .action(async (options: { path: string }) => {
      const dependencyScan = await scanDependencies(options.path);
      const dependencyHealth = calculateDependencyHealth(dependencyScan.findings);
      const score = calculateScore({ dependencyHealth });

      console.log(chalk.bold('Toolip Security Scorecard'));
      console.log('');
      console.log(`${chalk.dim('Dependency Health ....')} ${score.dependencyHealth}`);
      console.log(`${chalk.dim('Secret Hygiene .......')} ${score.secretHygiene}`);
      console.log(`${chalk.dim('Configuration ........')} ${score.configurationSecurity}`);
      console.log(`${chalk.dim('Git Safety ...........')} ${score.gitSafety}`);
      console.log('');
      console.log(`${chalk.dim('Overall Score ........')} ${score.overall}`);
      console.log(`${chalk.dim('Grade ................')} ${score.grade}`);
    });
}
