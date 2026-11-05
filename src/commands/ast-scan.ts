import type { Command } from 'commander';
import type { AnalyzerCommandDeps } from '../application/analyzer-command.js';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { AstSecurityAnalyzer } from '../analyzers/ast/ast-security-analyzer.js';
import {
  assessExecution,
  assessmentJson,
  finishAnalysis,
  isFailOn,
  type FailOn
} from '../application/analysis-status.js';
import { ToolipError } from '../errors/toolip-error.js';
import type { Finding } from '../contracts/finding.js';

type AstScanOptions = {
  path: string;
  json?: boolean;
  failOn?: string;
  failOnIncomplete?: boolean;
};

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
    console.log(`Fix: ${finding.remediation.summary}`);
  }

  console.log('');
}

export function registerAstScanCommand(
  program: Command,
  deps: AnalyzerCommandDeps = {}
): void {
  program
    .command('ast-scan')
    .description(
      'Run TypeScript Compiler API security analysis on JavaScript and TypeScript source files.'
    )
    .option('-p, --path <path>', 'Project path to inspect.', process.cwd())
    .option('--json', 'Print structured JSON output.')
    .option(
      '--fail-on <severity>',
      'Exit 2 at or above: critical, high, medium, low, none.',
      'high'
    )
    .option(
      '--no-fail-on-incomplete',
      'Do not exit 3 when eligible files were not analyzed (the run is still reported as partial).'
    )
    .action(async (options: AstScanOptions) => {
      if (!isFailOn(options.failOn)) {
        throw new ToolipError(
          `Invalid --fail-on value "${options.failOn}". Use critical, high, medium, low, info or none.`,
          { code: 'INVALID_FAIL_ON', exitCode: 1 }
        );
      }
      const failOn: FailOn = options.failOn;
      const runner = new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: deps.timeoutMs ?? 60_000
      });

      const [result] = await runner.run(
        [deps.analyzer ?? new AstSecurityAnalyzer()],
        {
          root: options.path
        }
      );

      if (!result) {
        throw new Error('The AST security analyzer returned no result.');
      }

      const assessment = assessExecution(result);

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              analyzer: result.analyzer,
              durationMs: result.durationMs,
              analysis: assessmentJson(assessment),
              summary: {
                filesAnalyzed: result.metadata?.filesAnalyzed ?? 0,
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
        console.log(`Files analyzed: ${result.metadata?.filesAnalyzed ?? 0}`);
        console.log(`Findings: ${result.findings.length}`);
        console.log('');

        for (const finding of result.findings) {
          printFinding(finding);
        }

        if (result.findings.length === 0 && assessment.state === 'complete') {
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

      finishAnalysis({
        assessment,
        findings: result.findings,
        failOn,
        failOnIncomplete: options.failOnIncomplete,
        quiet: options.json
      });
    });
}
