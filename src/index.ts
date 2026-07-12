#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';

import { registerAlternativesCommand } from './commands/alternatives.js';
import { registerCompareCommand } from './commands/compare.js';
import { registerDoctorCommand } from './commands/doctor.js';
import { registerGitAuditCommand } from './commands/git-audit.js';
import { registerHookCommand } from './commands/hook.js';
import { registerInspectCommand } from './commands/inspect.js';
import { registerLearnCommand } from './commands/learn.js';
import { registerLicensesCommand } from './commands/licenses.js';
import { registerPreCommitCommand } from './commands/pre-commit.js';
import { registerProfileCommand } from './commands/profile.js';
import { registerScanCommand } from './commands/scan.js';
import { registerScoreCommand } from './commands/score.js';
import { registerSelfTestCommand } from './commands/self-test.js';
import { registerTreeCommand } from './commands/tree.js';
import { registerVaultCommand } from './commands/vault.js';

import { TOOLIP_AUTHOR, TOOLIP_VERSION } from './config/version.js';
import { handleError } from './utils/error-handler.js';
import { registerVulnerabilitiesCommand } from './commands/vulnerabilities.js';
import { registerAstScanCommand } from './commands/ast-scan.js';
import { registerReachabilityCommand } from './commands/reachability.js';
import { registerInstallScriptsCommand } from './commands/install-scripts.js';
import { registerSbomCommand } from './commands/sbom.js';
import { registerHistoryCommand } from './commands/history.js';
import { registerConfigCommand } from './commands/config.js';
import { registerPackageHealthCommand } from './commands/package-health.js';
import { registerDependencyConfusionCommand } from './commands/dependency-confusion.js';

const program = new Command();

program
  .name('toolip')
  .description(
    'Developer-first supply chain security, security hygiene, and secrets management CLI.'
  )
  .version(TOOLIP_VERSION);

registerSelfTestCommand(program);
registerProfileCommand(program);
registerScanCommand(program);
registerDoctorCommand(program);
registerScoreCommand(program);
registerInspectCommand(program);
registerCompareCommand(program);
registerLicensesCommand(program);
registerAlternativesCommand(program);
registerTreeCommand(program);
registerVaultCommand(program);
registerGitAuditCommand(program);
registerPreCommitCommand(program);
registerHookCommand(program);
registerLearnCommand(program);

program.addHelpText(
  'after',
  `

${chalk.dim(
  `Built by ${TOOLIP_AUTHOR.name} (${TOOLIP_AUTHOR.handle}) — ${TOOLIP_AUTHOR.github}`
)}`
);

program.exitOverride();

try {
  registerVulnerabilitiesCommand(program);

registerAstScanCommand(program);

registerReachabilityCommand(program);

registerInstallScriptsCommand(program);

registerSbomCommand(program);

registerHistoryCommand(program);

registerConfigCommand(program);

registerPackageHealthCommand(program);

registerDependencyConfusionCommand(program);

await program.parseAsync(process.argv);
} catch (error) {
  handleError(error);
}
