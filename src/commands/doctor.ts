import type { Command } from 'commander';
import chalk from 'chalk';

export function registerDoctorCommand(program: Command): void {
  program
    .command('doctor')
    .description('Run a full project security hygiene audit.')
    .option('-p, --path <path>', 'Project path to audit.', process.cwd())
    .action((options: { path: string }) => {
      console.log(chalk.bold('Toolip Doctor'));
      console.log('');
      console.log(`Project: ${options.path}`);
      console.log('');
      console.log(chalk.yellow('Sprint 1 doctor foundation is installed. Security checks arrive in Sprint 3.'));
    });
}
