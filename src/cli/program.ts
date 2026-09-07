import chalk from 'chalk';
import { Command } from 'commander';
import { registerAlternativesCommand } from '../commands/alternatives.js';
import { registerAnnounceCommand } from '../commands/announce.js';
import { registerAstScanCommand } from '../commands/ast-scan.js';
import { registerAuditRepoCommand } from '../commands/audit-repo.js';
import { registerCompareCommand } from '../commands/compare.js';
import { registerConfigCommand } from '../commands/config.js';
import { registerDependencyConfusionCommand } from '../commands/dependency-confusion.js';
import { registerDiffCommand } from '../commands/diff.js';
import { registerDockerScanCommand } from '../commands/docker-scan.js';
import { registerDoctorCommand } from '../commands/doctor.js';
import { registerGitAuditCommand } from '../commands/git-audit.js';
import { registerGitHistoryCommand } from '../commands/git-history.js';
import { registerHistoryCommand } from '../commands/history.js';
import { registerHookCommand } from '../commands/hook.js';
import { registerInspectCommand } from '../commands/inspect.js';
import { registerInstallScriptsCommand } from '../commands/install-scripts.js';
import { registerLearnCommand } from '../commands/learn.js';
import { registerLicensesCommand } from '../commands/licenses.js';
import { registerMcpCommand } from '../commands/mcp.js';
import { registerMonorepoCommand } from '../commands/monorepo.js';
import { registerPackageHealthCommand } from '../commands/package-health.js';
import { registerPreCommitCommand } from '../commands/pre-commit.js';
import { registerProfileCommand } from '../commands/profile.js';
import { registerPublishCommand } from '../commands/publish.js';
import { registerReachabilityCommand } from '../commands/reachability.js';
import { registerSbomCommand } from '../commands/sbom.js';
import { registerScanCommand } from '../commands/scan.js';
import { registerScoreCommand } from '../commands/score.js';
import { registerSelfTestCommand } from '../commands/self-test.js';
import { registerTreeCommand } from '../commands/tree.js';
import { registerUpgradePrCommand } from '../commands/upgrade-pr.js';
import { registerVaultCommand } from '../commands/vault.js';
import { registerVulnerabilitiesCommand } from '../commands/vulnerabilities.js';
import { registerWatchCommand } from '../commands/watch.js';
import {
  TOOLIP_AUTHOR,
  TOOLIP_VERSION
} from '../config/version.js';

const registrations: Array<(program: Command) => void> = [
  registerSelfTestCommand,
  registerProfileCommand,
  registerScanCommand,
  registerDoctorCommand,
  registerScoreCommand,
  registerInspectCommand,
  registerCompareCommand,
  registerLicensesCommand,
  registerAlternativesCommand,
  registerTreeCommand,
  registerVaultCommand,
  registerGitAuditCommand,
  registerPreCommitCommand,
  registerHookCommand,
  registerLearnCommand,
  registerVulnerabilitiesCommand,
  registerAstScanCommand,
  registerReachabilityCommand,
  registerInstallScriptsCommand,
  registerSbomCommand,
  registerHistoryCommand,
  registerConfigCommand,
  registerPackageHealthCommand,
  registerDependencyConfusionCommand,
  registerGitHistoryCommand,
  registerDockerScanCommand,
  registerMonorepoCommand,
  registerAuditRepoCommand,
  registerUpgradePrCommand,
  registerDiffCommand,
  registerPublishCommand,
  registerWatchCommand,
  registerAnnounceCommand,
  registerMcpCommand
];

export function createProgram(): Command {
  const program = new Command()
    .name('toolip')
    .description(
      'Developer-first supply chain security, security hygiene, and secrets management CLI.'
    )
    .version(TOOLIP_VERSION);

  for (const register of registrations) register(program);

  program.addHelpText(
    'after',
    `\n\n${chalk.dim(
      `Built by ${TOOLIP_AUTHOR.name} (${TOOLIP_AUTHOR.handle}) — ${TOOLIP_AUTHOR.github}`
    )}`
  );

  return program;
}
