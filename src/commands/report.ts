import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import { readPemKeyFile } from '../core/secure-key-file.js';
import type { ToolipReport } from '../core/report.js';
import { verifyReportEvidence } from '../core/report-signature.js';
import {
  readEvidenceTrustStore,
  resolveEvidenceTrust
} from '../core/evidence-trust-store.js';
import { readBoundedRegularFile } from '../core/bounded-file.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';
import { createScanBadge, renderScanBadgeSvg } from '../core/scan-badge.js';
import type { ReportEvidenceVerification } from '../core/report-signature.js';

const maxReportBytes = 8 * 1024 * 1024;

async function readReport(filePath: string): Promise<ToolipReport> {
  try {
    const bytes = await readBoundedRegularFile(filePath, maxReportBytes);
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
    throw new ToolipError(
      'Report is malformed, unreadable, or over the input limit.',
      {
        code: 'REPORT_INPUT_INVALID',
        exitCode: 1
      }
    );
  }
}

export function registerReportCommand(program: Command): void {
  const report = program
    .command('report')
    .description('Verify signed Toolip scan evidence.');

  report
    .command('badge <file>')
    .description(
      'Create a static, fail-closed scan badge from a bounded report (offline).'
    )
    .requiredOption('--output <file>', 'New .svg or .json output path.')
    .requiredOption(
      '--expected-revision <sha>',
      'Exact immutable 40-character Git revision bound to signed scan evidence.'
    )
    .option('--trust-store <file>', 'External trusted evidence key store.')
    .option('--project-root <path>', 'Project root for external trust policy.', process.cwd())
    .option('--public-key <file>', 'Direct trusted Ed25519 public key PEM.')
    .option('--key-id <id>', 'Trusted signing key identifier.')
    .option('--project-id <id>', 'Expected stable project identity for direct-key mode.')
    .option('--source-tree-sha256 <digest>', 'Required scanned source-tree SHA-256.')
    .action(
      async (
        file: string,
        options: {
          output: string;
          expectedRevision: string;
          trustStore?: string;
          projectRoot: string;
          publicKey?: string;
          keyId?: string;
          projectId?: string;
          sourceTreeSha256?: string;
        }
      ) => {
        if (!/^[a-f0-9]{40}$/u.test(options.expectedRevision))
          throw new ToolipError('Expected Git revision must be an exact 40-character lowercase SHA.', {
            code: 'BADGE_REVISION_INVALID',
            exitCode: 1
          });
        const format = path.extname(options.output).toLowerCase();
        if (format !== '.svg' && format !== '.json')
          throw new ToolipError('Badge output must be .svg or .json.', {
            code: 'BADGE_OUTPUT_INVALID',
            exitCode: 1
          });
        if (options.trustStore && (options.publicKey || options.projectId))
          throw new ToolipError('Trust-store and direct-key options cannot be combined.', {
            code: 'BADGE_TRUST_OPTIONS_INVALID',
            exitCode: 1
          });
        if ((options.trustStore || options.publicKey || options.projectId || options.keyId) &&
            (!options.keyId || (!options.trustStore && (!options.publicKey || !options.projectId))))
          throw new ToolipError('Trusted badge verification requires --key-id and either --trust-store or both --public-key and --project-id.', {
            code: 'BADGE_TRUST_OPTIONS_INVALID',
            exitCode: 1
          });
        const scanReport = await readReport(file);
        let verification: ReportEvidenceVerification = {
          status: 'unsigned',
          reason: 'signature-missing'
        };
        if (options.trustStore && options.keyId) {
          const store = await readEvidenceTrustStore(
            options.trustStore,
            options.projectRoot
          );
          const trust = resolveEvidenceTrust(store, options.keyId);
          verification = verifyReportEvidence(scanReport, {
            publicKeyPem: trust.publicKeyPem,
            trustedKeyId: trust.trustedKeyId,
            expectedProjectId: trust.expectedProjectId,
            maxAgeMs: trust.maxAgeMs,
            expectedSourceTreeSha256: options.sourceTreeSha256
          });
        } else if (options.publicKey && options.keyId && options.projectId) {
          verification = verifyReportEvidence(scanReport, {
            publicKeyPem: await readPemKeyFile(options.publicKey),
            trustedKeyId: options.keyId,
            expectedProjectId: options.projectId,
            expectedSourceTreeSha256: options.sourceTreeSha256
          });
        }
        const badge = createScanBadge(scanReport, verification, {
          expectedRevision: options.expectedRevision
        });
        const output = format === '.svg'
          ? renderScanBadgeSvg(badge)
          : `${serializeJsonOutputBounded(badge)}\n`;
        // Exclusive creation refuses symlinks and existing files rather than
        // silently replacing a README or another path selected by the caller.
        await writeFile(options.output, output, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
        console.log(serializeJsonOutputBounded({
          status: badge.status,
          verified: badge.verified,
          output: options.output
        }));
        if (badge.status !== 'policy-passing') process.exitCode = 2;
      }
    );
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
        console.log(serializeJsonOutputBounded(result));
        if (result.status !== 'verified') process.exitCode = 2;
      }
    );
}
