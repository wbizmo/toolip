import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import { TOOLIP_VERSION } from '../config/version.js';
import type { FindingSeverity } from '../contracts/finding.js';
import {
  hasFindingAtSeverity,
  scanPullRequestDiff
} from '../core/diff/pr-scan.js';
import { readGitHubPullRequestEvent } from '../core/diff/github-pr-event.js';
import { writeSarifReport } from '../core/report-writer.js';
import { sanitizeOutput } from '../core/safe-output.js';

const failOnValues = new Set<FindingSeverity>([
  'critical',
  'high',
  'medium',
  'low',
  'info'
]);

export function registerPrScanCommand(program: Command): void {
  program
    .command('pr-scan [base] [head]')
    .description(
      'Compare changed-file security findings against an exact Git baseline.'
    )
    .option('-p, --path <path>', 'Repository path.', process.cwd())
    .option(
      '--github-event <file>',
      'Bind this scan to exact base/head SHAs from a GitHub pull_request event JSON file.'
    )
    .option(
      '--github-repository <owner/repo>',
      'Expected base repository for --github-event.'
    )
    .option('--json', 'Print a sanitized JSON diff report.')
    .option('--sarif <file>', 'Write introduced findings as SARIF 2.1.0.')
    .option(
      '--online-advisories',
      'Explicitly query OSV for changed exact dependency instances; omitted by default.'
    )
    .option(
      '--allow-public-scope',
      'Allow public OSV queries for scoped npm names when --online-advisories is set.'
    )
    .option(
      '--fail-on <severity>',
      'Exit 2 when introduced findings meet this threshold: critical, high, medium, low or info.',
      'high'
    )
    .action(
      async (
        base: string | undefined,
        head: string | undefined,
        options: {
          path: string;
          githubEvent?: string;
          githubRepository?: string;
          json?: boolean;
          sarif?: string;
          failOn: string;
          onlineAdvisories?: boolean;
          allowPublicScope?: boolean;
        }
      ) => {
        if (
          Boolean(options.githubEvent) !== Boolean(options.githubRepository) ||
          (options.githubEvent && (base || head)) ||
          (!options.githubEvent && !base)
        )
          throw new ToolipError(
            'Use either a base revision and optional head revision, or --github-event with --github-repository.',
            { code: 'PR_SCAN_INPUT_INVALID', exitCode: 1 }
          );

        if (
          options.failOn !== 'none' &&
          !failOnValues.has(options.failOn as FindingSeverity)
        )
          throw new ToolipError(
            '--fail-on must be critical, high, medium, low, info or none.',
            {
              code: 'INVALID_FAIL_ON',
              exitCode: 1
            }
          );

        const githubContext = options.githubEvent
          ? await readGitHubPullRequestEvent(
              options.githubEvent,
              options.githubRepository as string
            )
          : undefined;
        const result = await scanPullRequestDiff(
          options.path,
          githubContext?.baseSha ?? (base as string),
          githubContext?.headSha ?? head ?? 'HEAD',
          undefined,
          {
            onlineAdvisories: options.onlineAdvisories,
            allowPublicScope: options.allowPublicScope
          }
        );
        if (options.sarif)
          await writeSarifReport(options.sarif, {
            findings: result.introduced,
            analysisState: result.analysisState,
            toolVersion: TOOLIP_VERSION
          });

        const output = sanitizeOutput(
          githubContext
            ? {
                ...result,
                githubPullRequest: {
                  repository: githubContext.repository,
                  number: githubContext.pullRequestNumber,
                  headRepository: githubContext.headRepository
                }
              }
            : result
        );
        if (options.json) {
          process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
        } else {
          process.stdout.write(
            `${[
              'Toolip Pull Request Security Diff',
              ...(githubContext
                ? [
                    `GitHub pull request: ${githubContext.repository}#${githubContext.pullRequestNumber} (head ${githubContext.headRepository})`
                  ]
                : []),
              `Range: ${result.base}..${result.head}`,
              `Changed files: ${result.changedFiles.length}`,
              `Introduced findings: ${result.introduced.length}`,
              `Fixed findings: ${result.fixed.length}`,
              `Unchanged findings: ${result.unchangedCount}`,
              ...(result.dependencyImpact
                ? [
                    `Dependency instances: ${result.dependencyImpact.basePackageCount} base -> ${result.dependencyImpact.headPackageCount} head; ${result.dependencyImpact.addedCount} added, ${result.dependencyImpact.removedCount} removed, ${result.dependencyImpact.versionChangedCount} version changes (${result.dependencyImpact.state}; advisories ${result.dependencyImpact.advisoryStatus}; ${result.dependencyImpact.introducedAdvisories.length} introduced, ${result.dependencyImpact.fixedAdvisories.length} fixed)`
                  ]
                : []),
              `Coverage: ${result.coverage} (${result.analysisState})`,
              ...(result.reasons.length
                ? [`Review required: ${result.reasons.join(', ')}`]
                : [])
            ].join('\n')}\n`
          );
        }

        if (result.analysisState === 'failed') process.exitCode = 3;
        else if (
          options.failOn !== 'none' &&
          hasFindingAtSeverity(
            result.introduced,
            options.failOn as FindingSeverity
          )
        )
          process.exitCode = 2;
        else process.exitCode = 0;
      }
    );
}
