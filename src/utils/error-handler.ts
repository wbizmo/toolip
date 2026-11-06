import chalk from 'chalk';
import { CommanderError } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import { redactSensitiveText } from '../core/safe-output.js';

/** Prints a sanitized CLI error and exits with the appropriate status code. */
export function handleError(error: unknown): never {
  if (error instanceof CommanderError) {
    if (
      error.code === 'commander.version' ||
      error.code === 'commander.helpDisplayed'
    ) {
      process.exit(0);
    }

    console.error(`${chalk.red('✖')} ${redactSensitiveText(error.message)}`);
    process.exit(error.exitCode || 1);
  }

  if (error instanceof ToolipError) {
    console.error(`${chalk.red('✖')} ${redactSensitiveText(error.message)}`);
    console.error(chalk.dim(`Code: ${error.code}`));
    process.exit(error.exitCode);
  }

  if (error instanceof Error) {
    console.error(`${chalk.red('✖')} ${redactSensitiveText(error.message)}`);
    process.exit(1);
  }

  console.error(`${chalk.red('✖')} Unknown Toolip error.`);
  process.exit(1);
}
