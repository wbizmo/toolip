import type { Command } from 'commander';
import { profileProject } from '../core/profile-project.js';
import { printProfile } from '../utils/output.js';

export function registerProfileCommand(program: Command): void {
  program
    .command('profile')
    .description('Fingerprint the current project and detect frameworks, languages, and tooling.')
    .option('-p, --path <path>', 'Project path to inspect.', process.cwd())
    .action(async (options: { path: string }) => {
      const profile = await profileProject(options.path);
      printProfile(profile);
    });
}
