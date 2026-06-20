#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { registerDoctorCommand } from './commands/doctor.js';
import { registerProfileCommand } from './commands/profile.js';
import { registerScanCommand } from './commands/scan.js';
import { registerSelfTestCommand } from './commands/self-test.js';

const program = new Command();

program
  .name('toolip')
  .description('Developer-first supply chain security, security hygiene, and secrets management CLI.')
  .version('0.1.0');

registerSelfTestCommand(program);
registerProfileCommand(program);
registerScanCommand(program);
registerDoctorCommand(program);

program.addHelpText(
  'after',
  `

${chalk.dim('Built by Ashibuogwu Williams (wbizmo) — https://github.com/wbizmo')}`
);

program.parse(process.argv);
