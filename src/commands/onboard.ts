import type { Command } from 'commander';
import { discoverOnboardingEcosystems } from '../core/onboarding/detect-ecosystems.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';

/**
 * Zero-config, strictly read-only discovery before a first scan. This command
 * never installs a dependency, creates a policy, executes repository scripts,
 * or misrepresents detected filenames as exact installed dependencies.
 */
export function registerOnboardCommand(program: Command): void {
  program.command('onboard')
    .description('Discover supported ecosystems locally and show a safe first-scan command.')
    .option('-p, --path <path>', 'Project directory to inspect.', process.cwd())
    .option('--json', 'Print only the bounded onboarding JSON contract.')
    .action(async (options: { path: string; json?: boolean }) => {
      const result = await discoverOnboardingEcosystems(options.path);
      if (options.json) {
        console.log(serializeJsonOutputBounded(result));
        return;
      }
      console.log('Toolip local-first onboarding (no files changed)');
      if (result.detected.length === 0) {
        console.log('No supported ecosystem manifest or lockfile was found.');
        console.log('A source-security scan may still be useful; coverage is not assumed complete.');
      } else {
        for (const entry of result.detected) {
          console.log(
            `- ${entry.ecosystem}: ${entry.confidence}; ` +
            `${entry.manifestCount} manifest(s), ${entry.lockfileCount} lock candidate(s)`
          );
          console.log(`  ${entry.caveat}`);
        }
      }
      console.log(`Run from the project directory: ${result.firstScanCommand}`);
      console.log('The command checks incomplete coverage instead of reporting a false all-clear.');
      console.log('Installation through npx may use the network even if the scan is offline.');
    });
}
