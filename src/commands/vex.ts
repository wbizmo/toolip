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
  type VexFormat
} from '../core/vex.js';
import { AdvisorySnapshotCache } from '../providers/intelligence/snapshot-cache.js';

const maxInputBytes = 16 * 1024 * 1024;

type VexScanOptions = {
  path: string;
  output: string;
  author: string;
  format: string;
  offline?: boolean;
  dataSnapshot?: string;
  maxAdvisoryAgeDays: string;
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
    .option('--max-advisory-age-days <days>', 'Maximum OSV snapshot age.', '30')
    .action(async (options: VexScanOptions) => {
      if (options.format !== 'openvex' && options.format !== 'cyclonedx')
        throw new Error('VEX format must be openvex or cyclonedx.');
      const maxDays = Number(options.maxAdvisoryAgeDays);
      if (!Number.isFinite(maxDays) || maxDays < 0)
        throw new Error('--max-advisory-age-days must be non-negative.');
      const cache = options.dataSnapshot
        ? await AdvisorySnapshotCache.open(options.dataSnapshot)
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
    .command('validate')
    .requiredOption('-i, --input <file>', 'VEX JSON input file.')
    .requiredOption('-f, --format <format>', 'openvex or cyclonedx.')
    .action(async (options: { input: string; format: string }) => {
      if (options.format !== 'openvex' && options.format !== 'cyclonedx')
        throw new Error('VEX format must be openvex or cyclonedx.');
      const fileStat = await stat(options.input);
      if (fileStat.size > maxInputBytes)
        throw new Error('VEX input exceeds the 16 MiB limit.');
      const document = JSON.parse(
        await readFile(options.input, 'utf8')
      ) as unknown;
      const assessments = parseVexDocument(
        document,
        options.format as VexFormat
      );
      console.log(
        JSON.stringify(
          {
            state: 'valid',
            format: options.format,
            assessments: assessments.length,
            notAffected: assessments.filter(
              (assessment) => assessment.status === 'not_affected'
            ).length
          },
          null,
          2
        )
      );
    });
}
