import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import type { Finding } from '../../contracts/finding.js';
import path from 'node:path';
import { coverageOf } from '../../contracts/analysis.js';
import { createScannerContext } from '../../core/scanner-context.js';
import type { ScannerContext } from '../../core/scanner-context.js';
import { bindSourceProvenance } from '../../core/source-provenance.js';
import {
  TextFileReader,
  type TextFileReadResult
} from '../../core/text-file-reader.js';
import type { ProjectFile } from '../../core/file-walker.js';
import { analyzeAstProjectInWorker } from './project-analysis-worker-client.js';

const supportedExtensions = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs']);

/** Filters generated declarations and unsupported file types from AST analysis. */
function shouldAnalyze(relativePath: string, extension: string): boolean {
  if (!supportedExtensions.has(extension)) return false;
  if (relativePath.endsWith('.d.ts')) return false;
  if (relativePath.endsWith('.map')) return false;
  if (relativePath.startsWith('dist/')) return false;
  return true;
}

export class AstSecurityAnalyzer implements Analyzer {
  readonly id = 'typescript-ast-security';
  readonly version = '1.0.0';
  /** The TypeScript compiler is CPU-heavy; run it where the deadline is enforceable. */
  readonly isolation = {
    module: import.meta.url,
    exportName: 'AstSecurityAnalyzer'
  };

  /** Analyzes eligible source snapshots and reports incomplete reads. */
  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const scannerContext =
      (context.options?.scannerContext as ScannerContext | undefined) ??
      (await createScannerContext(context.root));
    if (path.resolve(scannerContext.root) !== path.resolve(context.root)) {
      throw new Error('scanner context root does not match the analyzer root');
    }
    const reader = new TextFileReader(undefined, { root: scannerContext.root });
    const findings = [];
    const warnings: string[] = [];
    let filesAnalyzed = 0;
    let eligible = 0;
    let skipped = 0;
    let failed = 0;
    let cancelled = false;
    const sources: {
      file: ProjectFile;
      read: Extract<TextFileReadResult, { status: 'ok' }>;
    }[] = [];

    for (const file of scannerContext.files) {
      if (!shouldAnalyze(file.relativePath, file.extension)) {
        continue;
      }

      eligible += 1;
      if (cancelled) {
        warnings.push(`${file.relativePath}: skipped (cancelled)`);
        skipped += 1;
        continue;
      }
      const read = await reader.read(
        file.absolutePath,
        context.signal,
        file.snapshot
      );

      if (read.status !== 'ok') {
        warnings.push(`${file.relativePath}: skipped (${read.status})`);
        skipped += 1;
        if (read.status === 'cancelled') {
          cancelled = true;
        }
        continue;
      }

      sources.push({ file, read });
    }

    let projectFindingsByPath:
      ReadonlyMap<string, readonly Finding[]> | undefined;
    let projectAnalysisIncomplete = false;
    if (sources.length > 0) {
      try {
        ({ findingsByPath: projectFindingsByPath } =
          await analyzeAstProjectInWorker(
            sources.map(({ file, read }) => ({
              filePath: file.relativePath,
              absolutePath: file.absolutePath,
              content: read.content
            })),
            { signal: context.signal }
          ));
      } catch {
        projectAnalysisIncomplete = true;
        skipped += Math.max(1, sources.length);
        warnings.push(
          'TypeScript project analysis was incomplete or cancelled; source findings were not reported as clean'
        );
      }
    }

    for (const { file, read } of sources) {
      const projectFindings = projectFindingsByPath?.get(file.relativePath);
      if (!projectFindings) continue;
      try {
        findings.push(
          ...bindSourceProvenance([...projectFindings], file, read)
        );
      } catch {
        failed += 1;
        warnings.push(
          `${file.relativePath}: AST analysis failed or exceeded its work budget`
        );
        continue;
      }

      filesAnalyzed += 1;
    }

    return {
      analyzer: this.id,
      durationMs: Math.round(performance.now() - startedAt),
      findings,
      coverage: coverageOf({
        eligible,
        scanned: filesAnalyzed,
        skipped,
        failed,
        cancelled
      }),
      warnings: warnings.length > 0 ? warnings : undefined,
      metadata: {
        filesAnalyzed,
        bytesAnalyzed: reader.usage.bytesRead,
        findings: findings.length,
        parser: 'typescript-compiler-api',
        taintAnalysis: projectFindingsByPath
          ? 'bounded-snapshot-symbol-graph-v1'
          : projectAnalysisIncomplete
            ? 'unavailable-incomplete-project-analysis'
            : 'not-applicable',
        taintWorkLimitPerFile: 250_000,
        taintWorkLimitPerProject: 8_000_000,
        interproceduralInputLimits: {
          files: 50_000,
          bytes: 64 * 1024 * 1024
        },
        crossFileAnalysis: projectFindingsByPath
          ? 'complete-for-resolved-snapshot-symbols'
          : projectAnalysisIncomplete
            ? 'incomplete'
            : 'not-applicable',
        sourceSinkModel: 'bounded-local-request-source-and-sink-heuristics-v1',
        limitations: [
          'Static request-source heuristics are not complete taint analysis.',
          'No finding-free result proves an application is free from injection or authorization defects.',
          'BOLA/IDOR requires application-specific ownership checks and runtime authorization tests.'
        ]
      }
    };
  }
}
