import { writeFile } from 'node:fs/promises';
import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import {
  verifyDistributionAsset,
  verifyDistributionManifest
} from '../core/distribution/manifest.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';
import { renderHomebrewCandidate } from '../core/distribution/homebrew.js';

/** Only verifies local files. Does not install, download or publish assets. */
export function registerDistributionCommand(program: Command): void {
  const dist = program.command('distribution')
    .description('Offline checks for immutable standalone distribution artifacts.');
  dist
    .command('homebrew-candidate <manifest>')
    .description('Render an unpublished Homebrew formula candidate from a verified signed manifest.')
    .requiredOption('--signature <file>', 'Detached manifest Ed25519 signature.')
    .requiredOption('--public-key <file>', 'Separately trusted operator key.')
    .requiredOption('--version <version>', 'Expected exact release version.')
    .requiredOption('--git-sha <sha>', 'Expected exact source revision.')
    .requiredOption('--output <file>', 'New local Toolip formula .rb file.')
    .action(async (
      manifestFile: string,
      options: {
        signature: string;
        publicKey: string;
        version: string;
        gitSha: string;
        output: string;
      }
    ) => {
      if (!options.output.endsWith('.rb'))
        throw new ToolipError('Homebrew candidate output must be a Ruby formula file.', {
          code: 'HOMEBREW_OUTPUT_INVALID', exitCode: 1
        });
      const manifest = await verifyDistributionManifest({
        manifestFile,
        signatureFile: options.signature,
        trustedPublicKeyFile: options.publicKey,
        expectedVersion: options.version,
        expectedGitSha: options.gitSha
      });
      const candidate = renderHomebrewCandidate(manifest);
      // No cross-repo write, version tag, release, or formula publication.
      await writeFile(options.output, candidate.formula, {
        encoding: 'utf8', flag: 'wx', mode: 0o600
      });
      console.log(serializeJsonOutputBounded({
        schema: candidate.schema,
        status: candidate.status,
        published: candidate.published,
        tapRepository: candidate.tapRepository,
        output: options.output
      }));
    });

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
