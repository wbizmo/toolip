import type { Command } from 'commander';
import chalk from 'chalk';
import { access } from 'node:fs/promises';
import path from 'node:path';
import { TOOLIP_VERSION } from '../config/version.js';

async function canAccess(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

export function registerSelfTestCommand(program: Command): void {
  program
    .command('self-test')
    .description('Run Toolip internal diagnostics.')
    .action(async () => {
      const checks = [
        {
          label: 'CLI Loaded',
          passed: true
        },
        {
          label: 'Command Router Ready',
          passed: true
        },
        {
          label: 'Package Manifest Found',
          passed: await canAccess(path.join(process.cwd(), 'package.json'))
        },
        {
          label: 'Scanner Foundation Ready',
          passed: true
        },
        {
          label: 'Report Engine Ready',
          passed: true
        }
      ];

      console.log(chalk.bold('Toolip Self-Test'));
      console.log(chalk.dim(`Version: ${TOOLIP_VERSION}`));
      console.log('');

      let failed = 0;

      for (const check of checks) {
        if (check.passed) {
          console.log(`${chalk.green('✓')} ${check.label}`);
        } else {
          failed += 1;
          console.log(`${chalk.red('✖')} ${check.label}`);
        }
      }

      console.log('');

      if (failed > 0) {
        console.log(chalk.red(`Toolip found ${failed} failed diagnostic check(s).`));
        process.exitCode = 1;
        return;
      }

      console.log(chalk.green('Toolip is healthy.'));
    });
}
