import chalk from 'chalk';
import { ToolipError } from '../errors/toolip-error.js';

export function handleError(error: unknown): never {
  if (error instanceof ToolipError) {
    console.error(`${chalk.red('✖')} ${error.message}`);
    console.error(chalk.dim(`Code: ${error.code}`));
    process.exit(error.exitCode);
  }

  if (error instanceof Error) {
    console.error(`${chalk.red('✖')} ${error.message}`);
    process.exit(1);
  }

  console.error(`${chalk.red('✖')} Unknown Toolip error.`);
  process.exit(1);
}
