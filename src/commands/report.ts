import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import { readPemKeyFile } from '../core/secure-key-file.js';
import type { ToolipReport } from '../core/report.js';
import { verifyReportEvidence } from '../core/report-signature.js';
import {
  readEvidenceTrustStore,
  resolveEvidenceTrust
} from '../core/evidence-trust-store.js';

const maxReportBytes = 8 * 1024 * 1024;

async function readReport(filePath: string): Promise<ToolipReport> {
  const named = await lstat(filePath);
  if (named.isSymbolicLink() || !named.isFile() || named.size > maxReportBytes)
    throw new ToolipError('Report must be a bounded regular file.', {
      code: 'REPORT_INPUT_INVALID',
      exitCode: 1
    });
  const handle = await open(
    filePath,
    constants.O_RDONLY |
      (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
  );
  try {
    const opened = await handle.stat();
    const after = await lstat(filePath);
    if (
      !opened.isFile() ||
      after.isSymbolicLink() ||
      opened.dev !== after.dev ||
      opened.ino !== after.ino ||
      opened.size > maxReportBytes
    )
      throw new ToolipError('Report changed while it was being opened.', {
        code: 'REPORT_INPUT_CHANGED',
        exitCode: 1
      });
    const bytes = await handle.readFile();
    if (bytes.length > maxReportBytes)
      throw new ToolipError('Report exceeds the input size limit.', {
        code: 'REPORT_INPUT_INVALID',
        exitCode: 1
      });
    const report = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    ) as unknown;
    if (
      !report ||
      typeof report !== 'object' ||
      Array.isArray(report) ||
      (report as Record<string, unknown>).tool !== 'toolip' ||
      !Array.isArray((report as Record<string, unknown>).findings) ||
      !(report as Record<string, unknown>).summary
    )
      throw new ToolipError('File does not contain a Toolip JSON report.', {
        code: 'REPORT_INPUT_INVALID',
        exitCode: 1
      });
    return report as ToolipReport;
  } catch (error) {
    if (error instanceof ToolipError) throw error;
    throw new ToolipError('Report JSON is malformed or unreadable.', {
      code: 'REPORT_INPUT_INVALID',
      exitCode: 1
    });
  } finally {
    await handle.close();
  }
}

export function registerReportCommand(program: Command): void {
  const report = program
    .command('report')
    .description('Verify signed Toolip scan evidence.');
  report
    .command('verify <file>')
    .description(
      'Verify report integrity, project identity, trusted key and signature age.'
    )
    .option('--public-key <file>', 'Trusted Ed25519 public key PEM file.')
    .requiredOption('--key-id <id>', 'Expected key identifier.')
    .option('--project-id <id>', 'Expected stable project identifier.')
    .option(
      '--project-root <path>',
      'Verified project root used to keep the trust store outside project-controlled files.',
      process.cwd()
    )
    .option(
      '--trust-store <file>',
      'External versioned trust store with active, expired and revoked key IDs.'
    )
    .option(
      '--scanner-artifact-sha256 <digest>',
      'Require this exact trusted Toolip runtime artifact digest.'
    )
    .option(
      '--source-tree-sha256 <digest>',
      'Require this exact captured project source-tree digest to reject stale or replayed evidence.'
    )
    .option(
      '--max-age-days <days>',
      'Maximum accepted signature age (direct-key mode).'
    )
    .action(
      async (
        file: string,
        options: {
          publicKey?: string;
          keyId: string;
          projectId?: string;
          projectRoot: string;
          trustStore?: string;
          scannerArtifactSha256?: string;
          sourceTreeSha256?: string;
          maxAgeDays?: string;
        }
      ) => {
        let publicKeyPem: string;
        let projectId: string;
        let maxAgeDays = options.maxAgeDays ? Number(options.maxAgeDays) : 90;
        if (options.trustStore) {
          if (options.publicKey || options.projectId || options.maxAgeDays)
            throw new ToolipError(
              '--trust-store cannot be combined with --public-key, --project-id, or --max-age-days.',
              { code: 'REPORT_TRUST_OPTIONS_INVALID', exitCode: 1 }
            );
          const store = await readEvidenceTrustStore(
            options.trustStore,
            options.projectRoot
          );
          const trust = resolveEvidenceTrust(store, options.keyId);
          publicKeyPem = trust.publicKeyPem;
          projectId = trust.expectedProjectId;
          maxAgeDays = store.maxAgeDays;
        } else {
          if (!options.publicKey || !options.projectId)
            throw new ToolipError(
              'Direct-key verification requires --public-key, --key-id, and --project-id; use --trust-store for managed key lifecycle.',
              { code: 'REPORT_TRUST_OPTIONS_INVALID', exitCode: 1 }
            );
          publicKeyPem = await readPemKeyFile(options.publicKey);
          projectId = options.projectId;
        }
        if (!Number.isFinite(maxAgeDays) || maxAgeDays < 0 || maxAgeDays > 365)
          throw new ToolipError('--max-age-days must be between 0 and 365.', {
            code: 'REPORT_MAX_AGE_INVALID',
            exitCode: 1
          });
        const scanReport = await readReport(file);
        const result = verifyReportEvidence(scanReport, {
          publicKeyPem,
          trustedKeyId: options.keyId,
          expectedProjectId: projectId,
          expectedScannerArtifactSha256: options.scannerArtifactSha256,
          expectedSourceTreeSha256: options.sourceTreeSha256,
          maxAgeMs: maxAgeDays * 24 * 60 * 60 * 1000
        });
        console.log(JSON.stringify(result, null, 2));
        if (result.status !== 'verified') process.exitCode = 2;
      }
    );
}
