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
import { readSecretInputs } from '../utils/secret-input.js';

export function registerVaultCommand(program: Command): void {
  const vault = program
    .command('vault')
    .description('Manage encrypted local secrets with Toolip Vault. Secrets are read from hidden prompts or stdin, never argv.');

  vault
    .command('init')
    .description('Initialize an encrypted local vault.')
    .action(async () => {
      const [password] = await readSecretInputs(['Master password']);
      await initVault(password);
      console.log(`${chalk.green('✓')} Toolip Vault initialized.`);
    });

  vault
    .command('set <key>')
    .description('Store or update a secret. Reads secret value, then master password, from hidden prompts or stdin.')
    .option('--env <env>', 'Secret environment.', 'development')
    .action(async (key: string, options: { env: string }) => {
      const [value, password] = await readSecretInputs(['Secret value', 'Master password']);
      await setSecret({
        key,
        value,
        env: options.env,
        masterPassword: password
      });

      console.log(`${chalk.green('✓')} Stored ${key} for ${options.env}.`);
    });

  vault
    .command('get <key>')
    .description('Retrieve a secret value.')
    .option('--env <env>', 'Secret environment.', 'development')
    .action(async (key: string, options: { env: string }) => {
      const [password] = await readSecretInputs(['Master password']);
      const secret = await getSecret({
        key,
        env: options.env,
        masterPassword: password
      });

      console.log(secret.value);
    });

  vault
    .command('list')
    .description('List secret names without revealing values.')
    .option('--env <env>', 'Filter by environment.')
    .action(async (options: { env?: string }) => {
      const [password] = await readSecretInputs(['Master password']);
      const secrets = await listSecrets({
        env: options.env,
        masterPassword: password
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
    .action(async (key: string, options: { env: string }) => {
      const [password] = await readSecretInputs(['Master password']);
      const deleted = await deleteSecret({
        key,
        env: options.env,
        masterPassword: password
      });

      console.log(deleted ? `${chalk.green('✓')} Deleted ${key}.` : chalk.yellow(`No secret found for ${key}.`));
    });

  vault
    .command('export')
    .description('Export secrets as shell-compatible environment lines.')
    .option('--env <env>', 'Filter by environment.')
    .action(async (options: { env?: string }) => {
      const [password] = await readSecretInputs(['Master password']);
      const output = await exportEnv({
        env: options.env,
        masterPassword: password
      });

      console.log(output);
    });
}
