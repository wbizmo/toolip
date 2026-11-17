import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import {
  verifyDistributionAsset,
  verifyDistributionManifest
} from '../core/distribution/manifest.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';

/** Only verifies local files. Does not install, download or publish assets. */
export function registerDistributionCommand(program: Command): void {
  const dist = program.command('distribution')
    .description('Offline checks for immutable standalone distribution artifacts.');
  dist
    .command('verify-asset <manifest>')
    .description('Verify a signed manifest and the selected local artifact digest.')
    .requiredOption('--signature <file>', 'Detached Ed25519 manifest signature file.')
    .requiredOption('--public-key <file>', 'Operator-provided trusted public key, obtained separately.')
    .requiredOption('--version <version>', 'Expected immutable release version.')
    .requiredOption('--git-sha <sha>', 'Expected immutable 40-character release source SHA.')
    .requiredOption('--target <target>', 'Signed operating system, architecture and libc target.')
    .requiredOption('--artifact <file>', 'Local archive for the selected signed target.')
    .action(async (
      manifestFile: string,
      options: {
        signature: string;
        publicKey: string;
        version: string;
        gitSha: string;
        target: string;
        artifact: string;
      }
    ) => {
      try {
        const manifest = await verifyDistributionManifest({
          manifestFile,
          signatureFile: options.signature,
          trustedPublicKeyFile: options.publicKey,
          expectedVersion: options.version,
          expectedGitSha: options.gitSha
        });
        const result = await verifyDistributionAsset(
          manifest, options.target, options.artifact
        );
        console.log(serializeJsonOutputBounded(result));
      } catch {
        // Report no archive path, key material or remote error body.
        throw new ToolipError(
          'Distribution manifest or artifact verification failed.',
          { code: 'DISTRIBUTION_VERIFY_FAILED', exitCode: 2 }
        );
      }
    });
}
