import type { Command } from 'commander';
import { readFile, stat } from 'node:fs/promises';
import type { AnalyzerCommandDeps } from '../application/analyzer-command.js';
import {
  assessExecution,
  assessmentJson,
  finishAnalysis,
  isFailOn,
  type FailOn
} from '../application/analysis-status.js';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { ToolipError } from '../errors/toolip-error.js';
import { OsvVulnerabilityAnalyzer } from '../analyzers/vulnerability/osv-analyzer.js';
import { AdvisorySnapshotCache } from '../providers/intelligence/snapshot-cache.js';
import { readPemKeyFile } from '../core/secure-key-file.js';
import {
  applyVexAssessments,
  parseVexDocument,
  type VexFormat
} from '../core/vex.js';

export function registerVulnerabilitiesCommand(
  program: Command,
  deps: AnalyzerCommandDeps = {}
): void {
  program
    .command('vulnerabilities')
    .alias('vulns')
    .description(
      'Match resolved supported-ecosystem dependencies against OSV.dev.'
    )
    .option('-p, --path <path>', 'Project path to inspect.', process.cwd())
    .option('--json', 'Print structured JSON output.')
    .option('--include-dev', 'Include development dependency findings.')
    .option(
      '--offline',
      'Disable advisory network requests and use local snapshot data only.'
    )
    .option(
      '--allow-public-scope',
      'Consent to sending scoped npm package names to the public OSV provider.'
    )
    .option(
      '--data-snapshot <file>',
      'Read and update this local advisory snapshot.'
    )
    .option(
      '--snapshot-public-key <file>',
      'Verify a signed advisory snapshot.'
    )
    .option(
      '--snapshot-public-key-id <id>',
      'Require the advisory snapshot signer key identifier.'
    )
    .option(
      '--snapshot-signing-key <file>',
      'Owner-only Ed25519 PEM key used to sign snapshot updates.'
    )
    .option(
      '--snapshot-signing-key-id <id>',
      'Identifier bound to the signature.'
    )
    .option(
      '--vex-file <file>',
      'Import VEX assessments for exact package instances.'
    )
    .option('--vex-format <format>', 'OpenVEX or CycloneDX.', 'openvex')
    .option(
      '--trust-vex-authority <authorities...>',
      'Allow these signed VEX authority names after signature verification.'
    )
    .option(
      '--vex-trusted-public-key <file>',
      'Verify imported VEX signatures with this trusted Ed25519 public key.'
    )
    .option('--vex-trusted-key-id <id>', 'Require this VEX signing key ID.')
    .option(
      '--max-advisory-age-days <days>',
      'Maximum OSV snapshot age before it is reported stale.',
      '30'
    )
    .option(
      '--fail-on <severity>',
      'Exit 2 at or above: critical, high, medium, low, none.',
      'none'
    )
    .option(
      '--no-fail-on-incomplete',
      'Do not exit 3 when the lookup was only partially completed.'
    )
    .action(
      async (options: {
        path: string;
        json?: boolean;
        includeDev?: boolean;
        offline?: boolean;
        allowPublicScope?: boolean;
        dataSnapshot?: string;
        snapshotPublicKey?: string;
        snapshotPublicKeyId?: string;
        snapshotSigningKey?: string;
        snapshotSigningKeyId?: string;
        maxAdvisoryAgeDays?: string;
        vexFile?: string;
        vexFormat?: string;
        trustVexAuthority?: string[];
        vexTrustedPublicKey?: string;
        vexTrustedKeyId?: string;
        failOn?: string;
        failOnIncomplete?: boolean;
      }) => {
        if (!isFailOn(options.failOn)) {
          throw new ToolipError(
            `Invalid --fail-on value "${options.failOn}". Use critical, high, medium, low, info or none.`,
            { code: 'INVALID_FAIL_ON', exitCode: 1 }
          );
        }
        const failOn: FailOn = options.failOn;
        const maxAdvisoryAgeDays = Number(options.maxAdvisoryAgeDays ?? '30');
        if (!Number.isFinite(maxAdvisoryAgeDays) || maxAdvisoryAgeDays < 0) {
          throw new ToolipError('Invalid --max-advisory-age-days value.', {
            code: 'INVALID_ADVISORY_AGE',
            exitCode: 1
          });
        }
        if (options.snapshotSigningKey && !options.snapshotSigningKeyId)
          throw new ToolipError(
            '--snapshot-signing-key-id is required when signing snapshot updates.',
            { code: 'SNAPSHOT_SIGNING_KEY_ID_REQUIRED', exitCode: 1 }
          );
        if (options.snapshotSigningKeyId && !options.snapshotSigningKey)
          throw new ToolipError(
            '--snapshot-signing-key-id requires --snapshot-signing-key.',
            { code: 'SNAPSHOT_SIGNING_KEY_REQUIRED', exitCode: 1 }
          );
        if (options.vexTrustedKeyId && !options.vexTrustedPublicKey)
          throw new ToolipError(
            '--vex-trusted-key-id requires --vex-trusted-public-key.',
            { code: 'INVALID_VEX_TRUST', exitCode: 1 }
          );
        const vexTrustedPublicKeyPem = options.vexTrustedPublicKey
          ? await readPemKeyFile(options.vexTrustedPublicKey)
          : undefined;
        if (
          !options.dataSnapshot &&
          (options.snapshotPublicKey ||
            options.snapshotPublicKeyId ||
            options.snapshotSigningKey ||
            options.snapshotSigningKeyId)
        )
          throw new ToolipError(
            'Snapshot key options require --data-snapshot.',
            { code: 'SNAPSHOT_FILE_REQUIRED', exitCode: 1 }
          );
        if (options.snapshotPublicKeyId && !options.snapshotPublicKey)
          throw new ToolipError(
            '--snapshot-public-key-id requires --snapshot-public-key.',
            { code: 'SNAPSHOT_KEY_ID_REQUIRES_KEY', exitCode: 1 }
          );
        const snapshot = options.dataSnapshot
          ? await AdvisorySnapshotCache.open(options.dataSnapshot, {
              trustedPublicKeyPem: options.snapshotPublicKey
                ? await readPemKeyFile(options.snapshotPublicKey)
                : undefined,
              trustedKeyId: options.snapshotPublicKeyId,
              signingPrivateKeyPem: options.snapshotSigningKey
                ? await readPemKeyFile(options.snapshotSigningKey, {
                    privateKey: true
                  })
                : undefined,
              signingKeyId: options.snapshotSigningKeyId,
              requireSignature: Boolean(options.snapshotPublicKey)
            })
          : undefined;
        const [result] = await new AnalyzerRunner({
          concurrency: 1,
          timeoutMs: deps.timeoutMs ?? 60_000
        }).run([deps.analyzer ?? new OsvVulnerabilityAnalyzer()], {
          root: options.path,
          cache: snapshot,
          options: {
            offline: options.offline ?? false,
            allowPublicScope: options.allowPublicScope === true,
            maxAdvisoryAgeMs: maxAdvisoryAgeDays * 24 * 60 * 60 * 1000
          }
        });
        await snapshot?.flush();

        if (!result) throw new Error('OSV analyzer returned no result.');
        const assessment = assessExecution(result);

        let findings = options.includeDev
          ? result.findings
          : result.findings.filter(
              (finding) => finding.metadata?.development !== true
            );
        let vexResult: ReturnType<typeof applyVexAssessments> | undefined;
        if (options.vexFile) {
          if (
            options.vexFormat !== 'openvex' &&
            options.vexFormat !== 'cyclonedx'
          )
            throw new ToolipError('VEX format must be openvex or cyclonedx.', {
              code: 'INVALID_VEX_FORMAT',
              exitCode: 1
            });
          const vexStat = await stat(options.vexFile);
          if (vexStat.size > 16 * 1024 * 1024)
            throw new ToolipError('VEX input exceeds the 16 MiB limit.', {
              code: 'VEX_INPUT_TOO_LARGE',
              exitCode: 1
            });
          const document = JSON.parse(
            await readFile(options.vexFile, 'utf8')
          ) as unknown;
          vexResult = applyVexAssessments(
            findings,
            parseVexDocument(document, options.vexFormat as VexFormat, {
              ...(vexTrustedPublicKeyPem
                ? { trustedPublicKeyPem: vexTrustedPublicKeyPem }
                : {}),
              ...(options.vexTrustedKeyId
                ? { trustedKeyId: options.vexTrustedKeyId }
                : {})
            }),
            { trustedAuthorities: options.trustVexAuthority ?? [] }
          );
          findings = vexResult.findings;
        }

        if (options.json) {
          console.log(
            JSON.stringify(
              {
                ...result,
                analysis: assessmentJson(assessment),
                findings,
                ...(vexResult
                  ? {
                      vex: {
                        applied: vexResult.applied,
                        suppressed: vexResult.suppressed,
                        rejected: vexResult.rejected
                      }
                    }
                  : {})
              },
              null,
              2
            )
          );
        } else if (assessment.state === 'failed') {
          console.log('Toolip Vulnerability Intelligence');
          console.log('');
          console.log(
            'Vulnerability lookup did not complete; no vulnerability result is available.'
          );
        } else {
          console.log('Toolip Vulnerability Intelligence');
          console.log('');
          console.log(
            `Dependencies checked: ${result.metadata?.dependenciesChecked ?? 0}`
          );
          console.log(`Known vulnerabilities: ${findings.length}`);
          if (vexResult) {
            console.log(`VEX assessments applied: ${vexResult.applied}`);
            console.log(
              `VEX not_affected findings suppressed: ${vexResult.suppressed.length}`
            );
            console.log(
              `VEX assessments rejected: ${vexResult.rejected.length}`
            );
          }
          console.log('');

          for (const finding of findings) {
            console.log(
              `[${finding.severity.toUpperCase()}] ${finding.metadata?.vulnerabilityId}`
            );
            console.log(
              `Package: ${finding.metadata?.package}@${finding.metadata?.installedVersion}`
            );
            console.log(`Summary: ${finding.title}`);
            if (finding.remediation?.summary)
              console.log(`Fix: ${finding.remediation.summary}`);
            console.log('');
          }

          if (
            findings.length === 0 &&
            vexResult &&
            vexResult.suppressed.length > 0
          ) {
            console.log(
              'All matched findings were suppressed by trusted, signed, unexpired not_affected assessments.'
            );
          } else if (findings.length === 0 && assessment.state === 'complete') {
            console.log(
              'No disclosed vulnerabilities matched the resolved supported-ecosystem dependency versions.'
            );
          }
        }

        finishAnalysis({
          assessment,
          findings,
          failOn,
          failOnIncomplete: options.failOnIncomplete,
          quiet: options.json
        });
      }
    );
}
