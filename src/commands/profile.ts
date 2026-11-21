import type { Command } from 'commander';
import { profileProject } from '../core/profile-project.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';
import { printProfile } from '../utils/output.js';

export function registerProfileCommand(program: Command): void {
  program
    .command('profile')
    .description(
      'Fingerprint the current project and detect frameworks, languages, and tooling.'
    )
    .option('-p, --path <path>', 'Project path to inspect.', process.cwd())
    .option('--json', 'Print profile as JSON.')
    .action(async (options: { path: string; json?: boolean }) => {
      const profile = await profileProject(options.path);

      if (options.json) {
        console.log(serializeJsonOutputBounded(profile));
        return;
      }

      printProfile(profile);
    });
}
