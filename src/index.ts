#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { registerDoctorCommand } from './commands/doctor.js';
import { registerProfileCommand } from './commands/profile.js';
import { registerScanCommand } from './commands/scan.js';
import { registerScoreCommand } from './commands/score.js';
import { registerSelfTestCommand } from './commands/self-test.js';
import { TOOLIP_AUTHOR, TOOLIP_VERSION } from './config/version.js';
import { handleError } from './utils/error-handler.js';

const program = new Command();

program
  .name('toolip')
  .description('Developer-first supply chain security, security hygiene, and secrets management CLI.')
  .version(TOOLIP_VERSION);

registerSelfTestCommand(program);
registerProfileCommand(program);
registerScanCommand(program);
registerDoctorCommand(program);
registerScoreCommand(program);

program.addHelpText(
  'after',
  `

${chalk.dim(`Built by ${TOOLIP_AUTHOR.name} (${TOOLIP_AUTHOR.handle}) — ${TOOLIP_AUTHOR.github}`)}`
);

program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (error) {
  handleError(error);
}
