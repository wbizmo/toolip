import {
  access,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import {
  loadToolipConfig,
  TOOLIP_CONFIG_FILE
} from '../core/config/load.js';

async function exists(
  filePath: string
): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

export function registerConfigCommand(
  program: Command
): void {
  const command = program
    .command('config')
    .description(
      'Initialize and validate Toolip project configuration.'
    );

  command
    .command('init')
    .option(
      '-p, --path <path>',
      'Project path.',
      process.cwd()
    )
    .option(
      '--force',
      'Replace an existing configuration.'
    )
    .action(
      async (
        options: {
          path: string;
          force?: boolean;
        }
      ) => {
        const filePath = path.join(
          options.path,
          TOOLIP_CONFIG_FILE
        );

        if (
          !options.force &&
          await exists(filePath)
        ) {
          throw new Error(
            `${TOOLIP_CONFIG_FILE} already exists.`
          );
        }

        const config = {
          schemaVersion: '1.0',
          include: [],
          exclude: [
            'dist/**',
            'coverage/**'
          ],
          rules: {},
          suppressions: [],
          history: {
            enabled: true,
            maxEntries: 500
          },
          providers: {
            osv: {
              enabled: true,
              timeoutMs: 20000
            },
            depsDev: {
              enabled: true,
              timeoutMs: 20000
            }
          }
        };

        await writeFile(
          filePath,
          `${JSON.stringify(config, null, 2)}\n`,
          'utf8'
        );

        console.log(
          `Created ${filePath}`
        );
      }
    );

  command
    .command('validate')
    .option(
      '-p, --path <path>',
      'Project path.',
      process.cwd()
    )
    .action(async (options: { path: string }) => {
      await loadToolipConfig(options.path);
      console.log(
        'Toolip configuration is valid.'
      );
    });

  command
    .command('show')
    .option(
      '-p, --path <path>',
      'Project path.',
      process.cwd()
    )
    .action(async (options: { path: string }) => {
      const config =
        await loadToolipConfig(options.path);

      console.log(
        JSON.stringify(config, null, 2)
      );
    });
}
