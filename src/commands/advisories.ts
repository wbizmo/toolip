import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';
import { lookupGhsaNpmPackage } from '../providers/advisories/ghsa-npm.js';

/**
 * Opt-in public npm package metadata lookup. This is an evidence query, not
 * a scan of local project files and never an automatic background upload.
 */
export function registerAdvisoriesCommand(program: Command): void {
  program
    .command('advisories')
    .description('Optional public advisory evidence lookups; no telemetry.')
    .command('npm <name> <version>')
    .description('Look up GHSA evidence for one exact public npm package instance.')
    .option('--offline', 'Do not contact any advisory provider.')
    .option('--type <kind>', 'One GHSA type: reviewed, unreviewed, or malware.', 'reviewed')
    .option(
      '--allow-public-package-lookup',
      'Consent to send the exact npm package name to the GitHub Advisory Database.'
    )
    .action(
      async (
        name: string,
        version: string,
        options: {
          offline?: boolean;
          allowPublicPackageLookup?: boolean;
          type?: string;
        }
      ) => {
        if (options.offline && options.allowPublicPackageLookup)
          throw new ToolipError(
            'Offline mode cannot be combined with network lookup consent.',
            { code: 'OFFLINE_ADVISORY_LOOKUP_CONFLICT', exitCode: 1 }
          );
        if (options.type &&
            !['reviewed', 'unreviewed', 'malware'].includes(options.type))
          throw new ToolipError(
            'GHSA type must be reviewed, unreviewed, or malware.',
            { code: 'ADVISORY_TYPE_INVALID', exitCode: 1 }
          );
        const result = await lookupGhsaNpmPackage(name, version, {
          offline: options.offline,
          allowPublicPackageLookup: options.allowPublicPackageLookup,
          advisoryType: options.type as 'reviewed' | 'unreviewed' | 'malware'
        });
        console.log(serializeJsonOutputBounded(result));
        if (result.status === 'failed') process.exitCode = 3;
        else if (result.status !== 'complete') process.exitCode = 2;
        else if (result.advisories.some(
          (advisory) => advisory.affected === 'yes' &&
            !advisory.withdrawn
        )) process.exitCode = 2;
      }
    );
}
