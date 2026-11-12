import type { Command } from 'commander';
import chalk from 'chalk';
import {
  decideExit,
  describeAssessment,
  gatedFindings,
  isFailOn
} from '../application/analysis-status.js';
import { ToolipError } from '../errors/toolip-error.js';
import {
  createProjectSnapshot,
  scannerContextFromSnapshot
} from '../application/project-snapshot.js';
import { createScannerContext } from '../core/scanner-context.js';
import type { ScannerContext } from '../core/scanner-context.js';
import { createReport } from '../core/report.js';
import { writeReport } from '../core/report-writer.js';
import { runSecurityDoctor } from '../core/security-doctor.js';
import {
  loadRulePackForCli,
  type VerifiedRulePack
} from '../core/rule-packs.js';
import { TOOLIP_VERSION } from '../config/version.js';
import { printReportSummary, printScannerContext } from '../utils/output.js';
import { loadWasmAnalyzerPluginForCli } from '../core/analyzer-plugin.js';

export function registerDoctorCommand(program: Command): void {
  program
    .command('doctor')
    .description('Run a full project security hygiene audit.')
    .option('-p, --path <path>', 'Project path to audit.', process.cwd())
    .option('-o, --output <file>', 'Write doctor report to JSON or Markdown.')
    .option(
      '--fail-on <severity>',
      'Exit 2 at or above: critical, high, medium, low, none.',
      'none'
    )
    .option(
      '--fail-on-incomplete',
      'Exit 3 when eligible files could not be scanned (partial result).'
    )
    .option(
      '--rule-pack <file>',
      'Load one signed declarative security rule pack.'
    )
    .option(
      '--rule-pack-public-key <file>',
      'Trusted Ed25519 public key for the rule pack.'
    )
    .option(
      '--rule-pack-key-id <id>',
      'Expected key ID bound to the rule-pack signature.'
    )
    .option(
      '--allow-unsigned-rule-pack',
      'Explicitly trust one unsigned declarative rule pack for this local run.'
    )
    .option(
      '--analyzer-plugin <manifest>',
      'Load one signed capability-limited WebAssembly analyzer.'
    )
    .option(
      '--analyzer-plugin-public-key <file>',
      'One-off trusted Ed25519 public key for plugin migration.'
    )
    .option(
      '--analyzer-plugin-trust-store <file>',
      'Operator-owned plugin key trust store outside the scanned project.'
    )
    .option(
      '--analyzer-plugin-key-id <id>',
      'Expected analyzer plugin signing key ID.'
    )
    .option(
      '--enable-executable-plugins',
      'Explicitly opt in to signed WebAssembly analyzer execution.'
    )
    .action(
      async (options: {
        path: string;
        output?: string;
        failOn?: string;
        failOnIncomplete?: boolean;
        rulePack?: string;
        rulePackPublicKey?: string;
        rulePackKeyId?: string;
        allowUnsignedRulePack?: boolean;
        analyzerPlugin?: string;
        analyzerPluginPublicKey?: string;
        analyzerPluginTrustStore?: string;
        analyzerPluginKeyId?: string;
        enableExecutablePlugins?: boolean;
      }) => {
        if (!isFailOn(options.failOn)) {
          throw new ToolipError(
            `Invalid --fail-on value "${options.failOn}". Use critical, high, medium, low, info or none.`,
            { code: 'INVALID_FAIL_ON', exitCode: 1 }
          );
        }
        console.log(chalk.bold('Toolip Doctor'));
        console.log('');

        let rulePack: VerifiedRulePack | undefined;
        let analyzerPlugin: Awaited<
          ReturnType<typeof loadWasmAnalyzerPluginForCli>
        >;
        try {
          rulePack = await loadRulePackForCli({
            filePath: options.rulePack,
            publicKeyPath: options.rulePackPublicKey,
            trustedKeyId: options.rulePackKeyId,
            allowUnsignedLocalOverride: options.allowUnsignedRulePack
          });
          analyzerPlugin = await loadWasmAnalyzerPluginForCli({
            manifestPath: options.analyzerPlugin,
            publicKeyPath: options.analyzerPluginPublicKey,
            trustStorePath: options.analyzerPluginTrustStore,
            trustedKeyId: options.analyzerPluginKeyId,
            projectRoot: options.path,
            enabled: options.enableExecutablePlugins
          });
        } catch (error) {
          throw new ToolipError(
            error instanceof Error
              ? error.message
              : 'Security extension could not be loaded.',
            { code: 'SECURITY_EXTENSION_INVALID', exitCode: 1 }
          );
        }

        let snapshot:
          Awaited<ReturnType<typeof createProjectSnapshot>> | undefined;
        let context: ScannerContext;
        try {
          snapshot = await createProjectSnapshot(options.path);
          context = await scannerContextFromSnapshot(snapshot);
        } catch (error) {
          // Doctor can still produce a useful, explicitly incomplete result
          // when an eligible file exceeds snapshot budgets or changes during
          // capture. Its per-analyzer bounded readers record those failures
          // in coverage; other snapshot-based commands remain fail-closed.
          if (
            !(error instanceof Error) ||
            !error.message.startsWith('snapshot incomplete for ')
          )
            throw error;
          context = await createScannerContext(options.path);
          console.log(
            chalk.yellow(
              'Immutable snapshot could not capture every file; continuing with bounded live reads and incomplete coverage reporting.'
            )
          );
        }
        printScannerContext(context);

        const doctor = await runSecurityDoctor(context, {
          ...(snapshot ? { snapshot } : {}),
          rulePacks: rulePack ? [rulePack] : undefined,
          analyzerPlugins: analyzerPlugin ? [analyzerPlugin] : undefined,
          enableExecutablePlugins: options.enableExecutablePlugins
        });

        const report = createReport({
          version: TOOLIP_VERSION,
          command: 'doctor',
          root: context.root,
          findings: doctor.findings,
          analysis: {
            state: doctor.coverage.state,
            reasons: doctor.coverage.reason ? [doctor.coverage.reason] : []
          },
          analyzerPlugins: doctor.analyzerPlugins.map((plugin) => ({
            id: plugin.id,
            sha256: plugin.sha256,
            keyId: plugin.keyId,
            state: plugin.coverage.state,
            findings: plugin.findings
          }))
        });

        console.log('');
        console.log(chalk.bold('Security Hygiene'));
        const coverage = doctor.coverage;
        console.log(
          `${chalk.dim('Analysis:')} ${coverage.state === 'complete' ? chalk.green('COMPLETE') : chalk.yellow(coverage.state.toUpperCase())} (${coverage.scanned}/${coverage.eligible} eligible scanned, ${coverage.skipped} skipped, ${coverage.failed} failed, ${coverage.excluded ?? 0} excluded)`
        );
        if (coverage.state !== 'complete') {
          console.log(
            chalk.yellow(
              `Not an all-clear: ${coverage.reason ?? 'some eligible files were not scanned'}.`
            )
          );
        }
        console.log(
          `${chalk.dim('Files Discovered:')} ${doctor.summary.filesDiscovered}`
        );
        console.log(
          `${chalk.dim('Files Scanned:')} ${doctor.summary.filesScanned}`
        );
        console.log(
          `${chalk.dim('Files Skipped:')} ${doctor.summary.filesSkipped}`
        );
        console.log(
          `${chalk.dim('Read Failures:')} ${doctor.summary.readFailures}`
        );
        console.log(`${chalk.dim('Secrets:')} ${doctor.summary.secrets}`);
        console.log(
          `${chalk.dim('Dangerous Code:')} ${doctor.summary.dangerousCode}`
        );
        console.log(
          `${chalk.dim('Configuration:')} ${doctor.summary.configuration}`
        );
        console.log(
          `${chalk.dim('Security Headers:')} ${doctor.summary.headers}`
        );

        console.log('');
        printReportSummary(report);

        if (options.output) {
          await writeReport(options.output, report);
          console.log('');
          console.log(
            `${chalk.green('✓')} Report written to ${options.output}`
          );
        }

        const gated = gatedFindings(doctor.findings, options.failOn);
        const code = decideExit({
          state: coverage.state,
          gated: gated.length,
          failOnIncomplete: options.failOnIncomplete ?? false
        });
        if (code !== 0) {
          console.error(
            `Exit ${code}: ${describeAssessment({ state: coverage.state, reason: coverage.reason, execution: 'ok', eligible: coverage.eligible, scanned: coverage.scanned, skipped: coverage.skipped, failed: coverage.failed })}; ${gated.length} finding(s) at or above the gate.`
          );
          process.exitCode = code;
        }
      }
    );
}
