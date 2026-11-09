import { readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { assessExecution } from '../application/analysis-status.js';
import { OsvVulnerabilityAnalyzer } from '../analyzers/vulnerability/osv-analyzer.js';
import {
  exportCycloneDxVex,
  exportOpenVex,
  parseVexDocument,
  signVexDocument,
  type VexFormat
} from '../core/vex.js';
import { AdvisorySnapshotCache } from '../providers/intelligence/snapshot-cache.js';
import { readPemKeyFile } from '../core/secure-key-file.js';

const maxInputBytes = 16 * 1024 * 1024;

type VexScanOptions = {
  path: string;
  output: string;
  author: string;
  format: string;
  offline?: boolean;
  dataSnapshot?: string;
  snapshotPublicKey?: string;
  snapshotPublicKeyId?: string;
  maxAdvisoryAgeDays: string;
};

type VexSignOptions = {
  input: string;
  output: string;
  format: string;
  signingKey: string;
  keyId: string;
};

/** Registers VEX export and strict bounded document validation commands. */
export function registerVexCommand(program: Command): void {
  const vex = program
    .command('vex')
    .description(
      'Import, validate and export vulnerability exploitability assessments.'
    );

  vex
    .command('export')
    .requiredOption('-o, --output <file>', 'Write the VEX JSON document.')
    .requiredOption('--author <name>', 'VEX document author or authority.')
    .option('-p, --path <path>', 'Project path to scan.', process.cwd())
    .option('-f, --format <format>', 'openvex or cyclonedx.', 'openvex')
    .option('--offline', 'Disable advisory network requests.')
    .option(
      '--data-snapshot <file>',
      'Read and update a local advisory snapshot.'
    )
    .option(
      '--snapshot-public-key <file>',
      'Verify a signed advisory snapshot before using cached records.'
    )
    .option(
      '--snapshot-public-key-id <id>',
      'Require the advisory snapshot signer key identifier.'
    )
    .option('--max-advisory-age-days <days>', 'Maximum OSV snapshot age.', '30')
    .action(async (options: VexScanOptions) => {
      if (options.format !== 'openvex' && options.format !== 'cyclonedx')
        throw new Error('VEX format must be openvex or cyclonedx.');
      const maxDays = Number(options.maxAdvisoryAgeDays);
      if (!Number.isFinite(maxDays) || maxDays < 0)
        throw new Error('--max-advisory-age-days must be non-negative.');
      if (options.snapshotPublicKeyId && !options.snapshotPublicKey)
        throw new Error(
          '--snapshot-public-key-id requires --snapshot-public-key.'
        );
      if (
        (options.snapshotPublicKey || options.snapshotPublicKeyId) &&
        !options.dataSnapshot
      )
        throw new Error(
          'Snapshot verification options require --data-snapshot.'
        );
      const cache = options.dataSnapshot
        ? await AdvisorySnapshotCache.open(options.dataSnapshot, {
            trustedPublicKeyPem: options.snapshotPublicKey
              ? await readPemKeyFile(options.snapshotPublicKey)
              : undefined,
            trustedKeyId: options.snapshotPublicKeyId,
            requireSignature: Boolean(options.snapshotPublicKey)
          })
        : undefined;
      const [result] = await new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: 60_000
      }).run([new OsvVulnerabilityAnalyzer()], {
        root: options.path,
        cache,
        options: {
          offline: options.offline ?? false,
          maxAdvisoryAgeMs: maxDays * 86_400_000
        }
      });
      await cache?.flush();
      if (!result)
        throw new Error('Vulnerability analyzer returned no result.');
      const assessment = assessExecution(result);
      if (assessment.state !== 'complete') {
        throw new Error(
          `VEX export requires complete coverage; analysis is ${assessment.state}${assessment.reason ? `: ${assessment.reason}` : ''}.`
        );
      }
      const document =
        options.format === 'openvex'
          ? exportOpenVex(result.findings, { author: options.author })
          : exportCycloneDxVex(result.findings, { author: options.author });
      await writeFile(
        path.resolve(options.output),
        `${JSON.stringify(document, null, 2)}\n`,
        { encoding: 'utf8', mode: 0o600 }
      );
      console.log(`VEX document written to ${path.resolve(options.output)}.`);
    });

  vex
    .command('sign')
    .requiredOption('-i, --input <file>', 'Unsigned OpenVEX or CycloneDX JSON.')
    .requiredOption(
      '-o, --output <file>',
      'Write the signed VEX JSON document.'
    )
    .requiredOption('--signing-key <file>', 'Owner-only Ed25519 private key.')
    .requiredOption('--key-id <id>', 'Trusted signing key identifier.')
    .requiredOption('-f, --format <format>', 'openvex or cyclonedx.')
    .action(async (options: VexSignOptions) => {
      if (options.format !== 'openvex' && options.format !== 'cyclonedx')
        throw new Error('VEX format must be openvex or cyclonedx.');
      const fileStat = await stat(options.input);
      if (fileStat.size > maxInputBytes)
        throw new Error('VEX input exceeds the 16 MiB limit.');
      const document = JSON.parse(
        await readFile(options.input, 'utf8')
      ) as unknown;
      const signed = signVexDocument(
        document,
        options.format as VexFormat,
        await readPemKeyFile(options.signingKey, { privateKey: true }),
        options.keyId
      );
      await writeFile(
        path.resolve(options.output),
        `${JSON.stringify(signed, null, 2)}\n`,
        { encoding: 'utf8', mode: 0o600 }
      );
      console.log(
        `Signed VEX document written to ${path.resolve(options.output)}.`
      );
    });

  vex
    .command('validate')
    .requiredOption('-i, --input <file>', 'VEX JSON input file.')
    .requiredOption('-f, --format <format>', 'openvex or cyclonedx.')
    .option('--trusted-public-key <file>', 'Verify the VEX Ed25519 signature.')
    .option('--trusted-key-id <id>', 'Require this signing key identifier.')
    .action(
      async (options: {
        input: string;
        format: string;
        trustedPublicKey?: string;
        trustedKeyId?: string;
      }) => {
        if (options.format !== 'openvex' && options.format !== 'cyclonedx')
          throw new Error('VEX format must be openvex or cyclonedx.');
        if (options.trustedKeyId && !options.trustedPublicKey)
          throw new Error('--trusted-key-id requires --trusted-public-key.');
        const fileStat = await stat(options.input);
        if (fileStat.size > maxInputBytes)
          throw new Error('VEX input exceeds the 16 MiB limit.');
        const document = JSON.parse(
          await readFile(options.input, 'utf8')
        ) as unknown;
        const assessments = parseVexDocument(
          document,
          options.format as VexFormat,
          {
            ...(options.trustedPublicKey
              ? {
                  trustedPublicKeyPem: await readPemKeyFile(
                    options.trustedPublicKey
                  )
                }
              : {}),
            ...(options.trustedKeyId
              ? { trustedKeyId: options.trustedKeyId }
              : {})
          }
        );
        console.log(
          JSON.stringify(
            {
              state: 'valid',
              format: options.format,
              assessments: assessments.length,
              notAffected: assessments.filter(
                (assessment) => assessment.status === 'not_affected'
              ).length,
              signatureStatus: assessments[0]?.signatureStatus ?? 'unsigned',
              signatureKeyId: assessments[0]?.signatureKeyId
            },
            null,
            2
          )
        );
      }
    );
}
