import type { Command } from 'commander';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { AstSecurityAnalyzer } from '../analyzers/ast/ast-security-analyzer.js';
import type { Finding } from '../contracts/finding.js';

type AstScanOptions = {
  path: string;
  json?: boolean;
  failOn?: 'critical' | 'high' | 'medium' | 'low' | 'none';
};

const severityOrder = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
} as const;

function shouldFail(
  findings: Finding[],
  failOn: AstScanOptions['failOn']
): boolean {
  if (!failOn || failOn === 'none') {
    return false;
  }

  const threshold = severityOrder[failOn];

  return findings.some(
    (finding) =>
      severityOrder[finding.severity] >= threshold
  );
}

function printFinding(finding: Finding): void {
  console.log(
    `[${finding.severity.toUpperCase()}] ${finding.ruleId} ${finding.title}`
  );

  if (finding.location) {
    console.log(
      `Location: ${finding.location.file}:` +
      `${finding.location.line ?? 1}:` +
      `${finding.location.column ?? 1}`
    );
  }

  console.log(`Message: ${finding.message}`);

  if (finding.remediation?.summary) {
    console.log(
      `Fix: ${finding.remediation.summary}`
    );
  }

  console.log('');
}

export function registerAstScanCommand(
  program: Command
): void {
  program
    .command('ast-scan')
    .description(
      'Run TypeScript Compiler API security analysis on JavaScript and TypeScript source files.'
    )
    .option(
      '-p, --path <path>',
      'Project path to inspect.',
      process.cwd()
    )
    .option('--json', 'Print structured JSON output.')
    .option(
      '--fail-on <severity>',
      'Exit non-zero at or above: critical, high, medium, low, none.',
      'high'
    )
    .action(async (options: AstScanOptions) => {
      const runner = new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: 60_000
      });

      const [result] = await runner.run(
        [new AstSecurityAnalyzer()],
        {
          root: options.path
        }
      );

      if (!result) {
        throw new Error(
          'The AST security analyzer returned no result.'
        );
      }

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              analyzer: result.analyzer,
              durationMs: result.durationMs,
              summary: {
                filesAnalyzed:
                  result.metadata?.filesAnalyzed ?? 0,
                findings: result.findings.length,
                warnings: result.warnings?.length ?? 0
              },
              findings: result.findings,
              warnings: result.warnings ?? []
            },
            null,
            2
          )
        );
      } else {
        console.log('Toolip AST Security Analysis');
        console.log('');
        console.log(
          `Files analyzed: ${
            result.metadata?.filesAnalyzed ?? 0
          }`
        );
        console.log(
          `Findings: ${result.findings.length}`
        );
        console.log('');

        for (const finding of result.findings) {
          printFinding(finding);
        }

        if (result.findings.length === 0) {
          console.log(
            'No supported dangerous-code patterns were resolved through the AST.'
          );
        }

        if ((result.warnings?.length ?? 0) > 0) {
          console.log('');
          console.log('Warnings');

          for (const warning of result.warnings ?? []) {
            console.log(`- ${warning}`);
          }
        }
      }

      if (
        shouldFail(
          result.findings,
          options.failOn
        )
      ) {
        process.exitCode = 2;
      }
    });
}
