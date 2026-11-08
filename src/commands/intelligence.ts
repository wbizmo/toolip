import type { Command } from 'commander';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { OsvVulnerabilityAnalyzer } from '../analyzers/vulnerability/osv-analyzer.js';
import { AdvisorySnapshotCache } from '../providers/intelligence/snapshot-cache.js';
import { readPemKeyFile } from '../core/secure-key-file.js';

type SnapshotOptions = {
  path: string;
  file: string;
  maxAdvisoryAgeDays: string;
  signingKey?: string;
  signingKeyId?: string;
  publicKey?: string;
};

function ageLimitMs(days: string): number {
  const value = Number(days);
  if (!Number.isFinite(value) || value < 0)
    throw new Error('--max-advisory-age-days must be a non-negative number.');
  return value * 24 * 60 * 60 * 1000;
}

/** Registers explicit local advisory snapshot refresh and integrity verification. */
export function registerIntelligenceCommand(program: Command): void {
  const intelligence = program
    .command('intelligence')
    .description('Manage local vulnerability intelligence snapshots.');
  const snapshot = intelligence
    .command('snapshot')
    .description('Refresh or verify a hashed OSV, EPSS and CISA KEV snapshot.');

  snapshot
    .command('refresh')
    .requiredOption('--file <file>', 'Local output snapshot file.')
    .option(
      '-p, --path <path>',
      'Project whose resolved dependencies are queried.',
      process.cwd()
    )
    .option(
      '--max-advisory-age-days <days>',
      'Maximum accepted age of cached OSV records.',
      '30'
    )
    .option('--signing-key <file>', 'Owner-only Ed25519 PEM signing key.')
    .option(
      '--signing-key-id <id>',
      'Identifier bound to the snapshot signature.'
    )
    .action(async (options: SnapshotOptions) => {
      const maxAgeMs = ageLimitMs(options.maxAdvisoryAgeDays);
      if (Boolean(options.signingKey) !== Boolean(options.signingKeyId))
        throw new Error(
          '--signing-key and --signing-key-id must be supplied together.'
        );
      const cache = await AdvisorySnapshotCache.open(options.file, {
        signingPrivateKeyPem: options.signingKey
          ? await readPemKeyFile(options.signingKey, { privateKey: true })
          : undefined,
        signingKeyId: options.signingKeyId
      });
      const [result] = await new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: 60_000
      }).run([new OsvVulnerabilityAnalyzer()], {
        root: options.path,
        cache,
        options: {
          offline: false,
          refreshAdvisories: true,
          maxAdvisoryAgeMs: maxAgeMs
        }
      });
      if (result?.status !== 'ok') {
        throw new Error(
          result?.error ?? 'Vulnerability intelligence snapshot refresh failed.'
        );
      }
      await cache.flush();
      console.log(
        JSON.stringify(
          {
            state:
              result.coverage?.state === 'complete' &&
              (result.warnings?.length ?? 0) === 0
                ? 'complete'
                : 'partial',
            file: cache.filePath,
            records: cache.recordCount,
            generatedAt: cache.generatedAt,
            signatureStatus: cache.signatureStatus,
            advisories: result.metadata?.dependenciesChecked,
            warnings: result.warnings ?? []
          },
          null,
          2
        )
      );
    });

  snapshot
    .command('verify')
    .requiredOption('--file <file>', 'Local snapshot file to validate.')
    .option(
      '--max-advisory-age-days <days>',
      'Maximum age before the snapshot is reported stale.',
      '30'
    )
    .option(
      '--public-key <file>',
      'Trusted Ed25519 PEM key for signature verification.'
    )
    .action(
      async (
        options: Pick<
          SnapshotOptions,
          'file' | 'maxAdvisoryAgeDays' | 'publicKey'
        >
      ) => {
        const maxAgeMs = ageLimitMs(options.maxAdvisoryAgeDays);
        const cache = await AdvisorySnapshotCache.open(options.file, {
          trustedPublicKeyPem: options.publicKey
            ? await readPemKeyFile(options.publicKey)
            : undefined,
          requireSignature: Boolean(options.publicKey)
        });
        const ageMs = cache.snapshotAgeMs;
        const stale = ageMs === undefined || ageMs > maxAgeMs;
        console.log(
          JSON.stringify(
            {
              state: stale ? 'stale' : 'verified',
              integrity: 'sha256',
              signature: cache.signatureStatus,
              file: cache.filePath,
              records: cache.recordCount,
              generatedAt: cache.generatedAt,
              ageMs
            },
            null,
            2
          )
        );
        if (stale) process.exitCode = 3;
      }
    );
}
