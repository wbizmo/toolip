import type { Command } from 'commander';
import chalk from 'chalk';
import {
  deleteSecret,
  exportEnv,
  getSecret,
  initVault,
  listSecrets,
  setSecret
} from '../core/vault.js';

export function registerVaultCommand(program: Command): void {
  const vault = program
    .command('vault')
    .description('Manage encrypted local secrets with Toolip Vault.');

  vault
    .command('init')
    .description('Initialize an encrypted local vault.')
    .requiredOption('--password <password>', 'Master password.')
    .action(async (options: { password: string }) => {
      await initVault(options.password);
      console.log(`${chalk.green('✓')} Toolip Vault initialized.`);
    });

  vault
    .command('set <key> <value>')
    .description('Store or update a secret.')
    .option('--env <env>', 'Secret environment.', 'development')
    .requiredOption('--password <password>', 'Master password.')
    .action(async (key: string, value: string, options: { env: string; password: string }) => {
      await setSecret({
        key,
        value,
        env: options.env,
        masterPassword: options.password
      });

      console.log(`${chalk.green('✓')} Stored ${key} for ${options.env}.`);
    });

  vault
    .command('get <key>')
    .description('Retrieve a secret value.')
    .option('--env <env>', 'Secret environment.', 'development')
    .requiredOption('--password <password>', 'Master password.')
    .action(async (key: string, options: { env: string; password: string }) => {
      const secret = await getSecret({
        key,
        env: options.env,
        masterPassword: options.password
      });

      console.log(secret.value);
    });

  vault
    .command('list')
    .description('List secret names without revealing values.')
    .option('--env <env>', 'Filter by environment.')
    .requiredOption('--password <password>', 'Master password.')
    .action(async (options: { env?: string; password: string }) => {
      const secrets = await listSecrets({
        env: options.env,
        masterPassword: options.password
      });

      if (secrets.length === 0) {
        console.log(chalk.yellow('No secrets found.'));
        return;
      }

      for (const secret of secrets) {
        console.log(`${chalk.green('✓')} ${secret.key} ${chalk.dim(`(${secret.env})`)}`);
      }
    });

  vault
    .command('delete <key>')
    .description('Delete a secret.')
    .option('--env <env>', 'Secret environment.', 'development')
    .requiredOption('--password <password>', 'Master password.')
    .action(async (key: string, options: { env: string; password: string }) => {
      const deleted = await deleteSecret({
        key,
        env: options.env,
        masterPassword: options.password
      });

      console.log(deleted ? `${chalk.green('✓')} Deleted ${key}.` : chalk.yellow(`No secret found for ${key}.`));
    });

  vault
    .command('export')
    .description('Export secrets as shell-compatible environment lines.')
    .option('--env <env>', 'Filter by environment.')
    .requiredOption('--password <password>', 'Master password.')
    .action(async (options: { env?: string; password: string }) => {
      const output = await exportEnv({
        env: options.env,
        masterPassword: options.password
      });

      console.log(output);
    });
}
