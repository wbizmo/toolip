import type { Command } from 'commander';
import chalk from 'chalk';
import { randomUUID } from 'node:crypto';
import {
  decideExit,
  gatedFindings,
  isFailOn
} from '../application/analysis-status.js';
import {
  createProjectSnapshot,
  scannerContextFromSnapshot
} from '../application/project-snapshot.js';
import { buildSecurityScorecard } from '../application/security-scorecard.js';
import { ToolipError } from '../errors/toolip-error.js';
import { TOOLIP_VERSION } from '../config/version.js';
import { createReport } from '../core/report.js';
import { summarizeFindings } from '../core/report.js';
import { appendHistoryTransaction } from '../core/history/store.js';
import { historyFindingRecords } from '../core/history/baseline.js';
import { writeReport, writeSarifReport } from '../core/report-writer.js';
import { AdvisorySnapshotCache } from '../providers/intelligence/snapshot-cache.js';
import { readHmacKeyFile, readPemKeyFile } from '../core/secure-key-file.js';
import {
  scannerArtifactDigest,
  signReportEvidence
} from '../core/report-signature.js';
import {
  loadRulePackForCli,
  type VerifiedRulePack
} from '../core/rule-packs.js';
import { printReportSummary, printScannerContext } from '../utils/output.js';
import { loadWasmAnalyzerPluginForCli } from '../core/analyzer-plugin.js';
import {
  readNpmProvenancePolicy,
  type NpmProvenancePolicy
} from '../providers/npm/provenance.js';
import { parsePythonTargetProfileJson } from '../core/dependencies/python-target.js';
import { parseGoTargetProfileJson } from '../core/dependencies/go-target.js';

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan project dependencies and security hygiene indicators.')
    .option('-p, --path <path>', 'Project path to scan.', process.cwd())
    .option('-o, --output <file>', 'Write scan report to JSON or Markdown.')
    .option(
      '--sarif <file>',
      'Write sanitized SARIF 2.1.0 findings for GitHub or other CI consumers.'
    )
    .option(
      '--fail-on <severity>',
      'Exit 2 at or above: critical, high, medium, low, none.',
      'none'
    )
    .option(
      '--fail-on-incomplete',
      'Exit 3 when any score dimension could not be measured (partial result).'
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
    .option('--offline', 'Disable registry and advisory network requests.')
    .option(
      '--allow-go-tool-execution',
      'Explicitly run go list/go mod graph on the captured metadata; may query proxy.golang.org and sum.golang.org. Project source is never built or imported.'
    )
    .option(
      '--python-target <json>',
      'Resolve Python markers for one explicit target JSON profile; without it platform-dependent Python packages remain unknown.'
    )
    .option(
      '--go-target <json>',
      'Select one GOOS/GOARCH target profile for vendor source import resolution.'
    )
    .option(
      '--package-health',
      'Opt in to bounded npm maintainer, publisher, release and lifecycle-history signals.'
    )
    .option(
      '--licenses',
      'Include bounded deps.dev license metadata, unknown-license findings and provider metrics.'
    )
    .option(
      '--allow-public-scope',
      'Consent to sending scoped npm package names to public metadata and advisory providers.'
    )
    .option(
      '--npm-provenance-policy <file>',
      'Opt in to exact npm provenance verification with an operator policy stored outside the scanned project.'
    )
    .option('--no-history', 'Do not append this scan to local history.')
    .option(
      '--history-integrity-key <file>',
      'Opt in to an authenticated local history chain using a private 256-bit hex key.'
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
      '--evidence-signing-key <file>',
      'Owner-only Ed25519 key used to attest the JSON scan report.'
    )
    .option(
      '--evidence-signing-key-id <id>',
      'Trusted identifier for the report signing key.'
    )
    .option(
      '--evidence-project-id <id>',
      'Stable project identity bound into the signed report.'
    )
    .option(
      '--max-advisory-age-days <days>',
      'Maximum OSV snapshot age before it is reported stale.',
      '30'
    )
    .action(
      async (options: {
        path: string;
        output?: string;
        sarif?: string;
        failOn?: string;
        failOnIncomplete?: boolean;
        offline?: boolean;
        allowGoToolExecution?: boolean;
        pythonTarget?: string;
        goTarget?: string;
        packageHealth?: boolean;
        licenses?: boolean;
        allowPublicScope?: boolean;
        npmProvenancePolicy?: string;
        dataSnapshot?: string;
        snapshotPublicKey?: string;
        snapshotPublicKeyId?: string;
        snapshotSigningKey?: string;
        snapshotSigningKeyId?: string;
        evidenceSigningKey?: string;
        evidenceSigningKeyId?: string;
        evidenceProjectId?: string;
        maxAdvisoryAgeDays?: string;
        history?: boolean;
        historyIntegrityKey?: string;
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
        if (options.offline && options.allowGoToolExecution) {
          throw new ToolipError(
            '--allow-go-tool-execution cannot be combined with --offline.',
            { code: 'OFFLINE_TOOL_EXECUTION_CONFLICT', exitCode: 1 }
          );
        }
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
        const maxAdvisoryAgeDays = Number(options.maxAdvisoryAgeDays ?? '30');
        if (!Number.isFinite(maxAdvisoryAgeDays) || maxAdvisoryAgeDays < 0) {
          throw new ToolipError('Invalid --max-advisory-age-days value.', {
            code: 'INVALID_ADVISORY_AGE',
            exitCode: 1
          });
        }
        const historyIntegrity =
          options.history !== false && options.historyIntegrityKey
            ? await readHmacKeyFile(options.historyIntegrityKey)
            : undefined;
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
        const evidenceOptionsProvided = Boolean(
          options.evidenceSigningKey ||
          options.evidenceSigningKeyId ||
          options.evidenceProjectId
        );
        if (evidenceOptionsProvided && !options.evidenceSigningKey)
          throw new ToolipError(
            'Report evidence key ID and project ID require --evidence-signing-key.',
            { code: 'EVIDENCE_SIGNING_KEY_REQUIRED', exitCode: 1 }
          );
        if (
          options.evidenceSigningKey &&
          (!options.evidenceSigningKeyId || !options.evidenceProjectId)
        )
          throw new ToolipError(
            'Signed evidence requires --evidence-signing-key-id and --evidence-project-id.',
            { code: 'EVIDENCE_IDENTITY_REQUIRED', exitCode: 1 }
          );
        if (
          options.evidenceSigningKey &&
          !options.output?.toLowerCase().endsWith('.json')
        )
          throw new ToolipError(
            'Signed evidence requires a JSON --output file.',
            { code: 'EVIDENCE_JSON_OUTPUT_REQUIRED', exitCode: 1 }
          );
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
        console.log(chalk.bold('Toolip Scan'));
        console.log('');
        if (options.offline)
          console.log(
            chalk.yellow('Offline mode: network requests are disabled.')
          );
        if (options.allowGoToolExecution)
          console.log(
            chalk.yellow(
              'Go MVS resolution is enabled: Toolip will run the Go module graph commands on captured metadata and may contact the official Go module proxy and checksum database.'
            )
          );
        if (snapshot && snapshot.signatureStatus !== 'verified')
          console.log(
            chalk.yellow(
              `Advisory snapshot signature: ${snapshot.signatureStatus}; cached records are treated as untrusted.`
            )
          );

        const projectSnapshot = await createProjectSnapshot(options.path);
        let npmProvenancePolicy: NpmProvenancePolicy | undefined;
        if (options.npmProvenancePolicy) {
          if (options.offline) {
            throw new ToolipError(
              '--npm-provenance-policy cannot be used with --offline.',
              { code: 'OFFLINE_PROVENANCE_CONFLICT', exitCode: 1 }
            );
          }
          try {
            npmProvenancePolicy = await readNpmProvenancePolicy(
              options.npmProvenancePolicy,
              projectSnapshot.root
            );
          } catch (error) {
            throw new ToolipError(
              error instanceof Error
                ? error.message
                : 'npm provenance policy could not be loaded.',
              { code: 'NPM_PROVENANCE_POLICY_INVALID', exitCode: 1 }
            );
          }
        }
        const context = await scannerContextFromSnapshot(projectSnapshot);
        printScannerContext(context);

        const scorecard = await buildSecurityScorecard(
          context.root,
          {},
          {
            cache: snapshot,
            offline: options.offline,
            allowGoToolExecution: options.allowGoToolExecution,
            pythonTarget: options.pythonTarget
              ? parsePythonTargetProfileJson(options.pythonTarget)
              : undefined,
            goTarget: options.goTarget
              ? parseGoTargetProfileJson(options.goTarget)
              : undefined,
            includePackageHealth: options.packageHealth,
            includeLicenseAnalysis: options.licenses,
            rulePacks: rulePack ? [rulePack] : undefined,
            analyzerPlugins: analyzerPlugin ? [analyzerPlugin] : undefined,
            enableExecutablePlugins: options.enableExecutablePlugins,
            allowPublicScope: options.allowPublicScope,
            npmProvenancePolicy,
            maxAdvisoryAgeMs: maxAdvisoryAgeDays * 24 * 60 * 60 * 1000,
            scannerContext: context,
            projectSnapshot
          }
        );
        await snapshot?.flush();
        let historyWarning: string | undefined;
        if (options.history !== false) {
          try {
            const createdAt = new Date().toISOString();
            const counts = summarizeFindings(scorecard.findings);
            await appendHistoryTransaction(
              context.root,
              (current) => {
                const records = historyFindingRecords({
                  findings: scorecard.findings,
                  root: context.root,
                  createdAt,
                  previous: current.entries.at(-1)
                });
                return {
                  id: `scan:${createdAt}:${randomUUID()}`,
                  createdAt,
                  toolipVersion: TOOLIP_VERSION,
                  command: 'scan',
                  ...(scorecard.score.overall === null
                    ? {}
                    : { score: scorecard.score.overall }),
                  summary: {
                    critical: counts.critical,
                    high: counts.high,
                    medium: counts.medium,
                    low: counts.low,
                    info: counts.info,
                    total: counts.totalFindings
                  },
                  findingIds: scorecard.findings.map((finding) => finding.id),
                  findingFingerprints: records.map(
                    (record) => record.fingerprint
                  ),
                  findingRecords: records,
                  coverage: scorecard.coverage,
                  metadata: {
                    analysisState: scorecard.analysis.state,
                    scoreComplete: scorecard.score.complete
                  }
                };
              },
              undefined,
              historyIntegrity
            );
          } catch {
            historyWarning = 'Local scan history could not be updated.';
          }
        }
        let report = createReport({
          version: TOOLIP_VERSION,
          command: 'scan',
          root: context.root,
          findings: scorecard.findings,
          analysis: { ...scorecard.analysis, coverage: scorecard.coverage },
          analyzerPlugins: scorecard.analyzerPlugins.map((plugin) => ({
            id: plugin.id,
            sha256: plugin.sha256,
            keyId: plugin.keyId,
            state: plugin.coverage.state,
            findings: plugin.findings
          })),
          npmProvenance: scorecard.npmProvenance
        });
        if (options.evidenceSigningKey) {
          const privateKeyPem = await readPemKeyFile(
            options.evidenceSigningKey,
            { privateKey: true }
          );
          report = signReportEvidence(report, {
            privateKeyPem,
            keyId: options.evidenceSigningKeyId as string,
            projectId: options.evidenceProjectId as string,
            scannerArtifactSha256: await scannerArtifactDigest(),
            subject: scorecard.evidenceSubject
          });
          console.log(
            `${chalk.dim('Evidence:')} signed (${report.evidenceSignature?.keyId}, scanner ${report.evidenceSignature?.scannerArtifactSha256}, payload ${report.evidenceSignature?.payloadSha256})`
          );
        }

        if (scorecard.dependencySummary) {
          const summary = scorecard.dependencySummary;
          console.log('');
          console.log(chalk.bold('Dependency Intelligence'));
          console.log(
            `${chalk.dim('Total Dependencies:')} ${summary.totalDependencies}`
          );
          console.log(`${chalk.dim('Outdated:')} ${summary.outdated}`);
          console.log(`${chalk.dim('Deprecated:')} ${summary.deprecated}`);
          console.log(`${chalk.dim('High Risk:')} ${summary.highRisk}`);
          console.log(`${chalk.dim('Medium Risk:')} ${summary.mediumRisk}`);
          console.log(
            `${chalk.dim('Average Risk:')} ${summary.averageRiskScore}`
          );
        }

        if (scorecard.packageHealth) {
          console.log('');
          console.log(chalk.bold('Package Health Review Signals'));
          console.log(
            `${chalk.dim('Coverage:')} ${scorecard.packageHealth.coverage.scanned}/${scorecard.packageHealth.coverage.eligible} npm instances inspected`
          );
          console.log(
            `${chalk.dim('Signals:')} ${scorecard.packageHealth.findings.length}`
          );
        }

        if (scorecard.npmProvenance?.length) {
          const verified = scorecard.npmProvenance.filter(
            (item) => item.status === 'verified'
          ).length;
          console.log('');
          console.log(chalk.bold('npm Publisher Provenance'));
          console.log(
            `${chalk.dim('Verified:')} ${verified}/${scorecard.npmProvenance.length}`
          );
          if (verified !== scorecard.npmProvenance.length)
            console.log(
              chalk.yellow(
                `${scorecard.npmProvenance.length - verified} package(s) remain unverified; see the JSON report for per-package status.`
              )
            );
        }

        console.log(
          `${chalk.dim('Dependency Health:')} ${scorecard.score.dependencyHealth ?? 'N/A'}`
        );
        console.log(
          `${chalk.dim('Overall Grade:')} ${scorecard.score.grade ?? 'N/A (incomplete)'}`
        );

        console.log(
          `${chalk.dim('Analysis:')} ${scorecard.analysis.state === 'complete' ? chalk.green('COMPLETE') : chalk.yellow(scorecard.analysis.state.toUpperCase())}`
        );
        for (const reason of scorecard.analysis.reasons) {
          console.log(`  ${chalk.yellow('!')} ${reason}`);
        }
        const coverage = scorecard.coverage;
        console.log(
          `${chalk.dim('Coverage:')} ${coverage.scanned}/${coverage.eligible} scanned, ` +
            `${coverage.skipped} skipped, ${coverage.failed} failed, ` +
            `${coverage.excluded ?? 0} excluded`
        );
        if (scorecard.analysis.state !== 'complete') {
          console.log(
            chalk.yellow(
              'Not an all-clear: unmeasured dimensions may hide findings.'
            )
          );
        }

        console.log('');
        printReportSummary(report);

        if (scorecard.warnings.length > 0) {
          console.log('');
          console.log(chalk.yellow('Partial analysis warnings:'));
          for (const warning of scorecard.warnings) {
            console.log(`- ${warning}`);
          }
        }
        if (historyWarning) console.log(chalk.yellow(historyWarning));

        if (options.output) {
          await writeReport(options.output, report);
          console.log('');
          console.log(
            `${chalk.green('✓')} Report written to ${options.output}`
          );
        }
        if (options.sarif) {
          await writeSarifReport(options.sarif, {
            findings: scorecard.findings,
            analysisState: scorecard.analysis.state,
            toolVersion: TOOLIP_VERSION
          });
          console.log(
            `${chalk.green('✓')} SARIF report written to ${options.sarif}`
          );
        }

        const code = decideExit({
          state: scorecard.analysis.state,
          gated: gatedFindings(scorecard.findings, options.failOn).length,
          failOnIncomplete: options.failOnIncomplete ?? false
        });
        if (code !== 0) {
          console.error(`Exit ${code}: analysis ${scorecard.analysis.state}.`);
          process.exitCode = code;
        }
      }
    );
}
