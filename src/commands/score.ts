import type { Command } from 'commander';
import chalk from 'chalk';
import { calculateScore } from '../core/score.js';

export function registerScoreCommand(program: Command): void {
  program
    .command('score')
    .description('Calculate a Toolip security scorecard for the current project.')
    .action(() => {
      const score = calculateScore();

      console.log(chalk.bold('Toolip Security Scorecard'));
      console.log('');
      console.log(`${chalk.dim('Dependency Health ....')} ${score.dependencyHealth}`);
      console.log(`${chalk.dim('Secret Hygiene .......')} ${score.secretHygiene}`);
      console.log(`${chalk.dim('Configuration ........')} ${score.configurationSecurity}`);
      console.log(`${chalk.dim('Git Safety ...........')} ${score.gitSafety}`);
      console.log('');
      console.log(`${chalk.dim('Overall Score ........')} ${score.overall}`);
      console.log(`${chalk.dim('Grade ................')} ${score.grade}`);
      console.log('');
      console.log(chalk.yellow('Real scoring signals will be connected across Sprints 2, 3, and 4.'));
    });
}
