import { readFile } from 'node:fs/promises';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import { createScannerContext } from '../../core/scanner-context.js';
import { analyzeAstSource } from './source-analysis.js';

const supportedExtensions = new Set([
  'js',
  'jsx',
  'ts',
  'tsx',
  'mjs',
  'cjs'
]);

function shouldAnalyze(
  relativePath: string,
  extension: string
): boolean {
  if (!supportedExtensions.has(extension)) return false;
  if (relativePath.endsWith('.d.ts')) return false;
  if (relativePath.endsWith('.map')) return false;
  if (relativePath.startsWith('dist/')) return false;
  return true;
}

export class AstSecurityAnalyzer implements Analyzer {
  readonly id = 'typescript-ast-security';
  readonly version = '1.0.0';

  async analyze(
    context: AnalyzerContext
  ): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const scannerContext = await createScannerContext(
      context.root
    );
    const findings = [];
    const warnings: string[] = [];
    let filesAnalyzed = 0;

    for (const file of scannerContext.files) {
      if (
        !shouldAnalyze(
          file.relativePath,
          file.extension
        )
      ) {
        continue;
      }

      if (context.signal?.aborted) {
        throw new Error('AST security analysis was cancelled.');
      }

      try {
        const content = await readFile(
          file.absolutePath,
          'utf8'
        );

        findings.push(
          ...analyzeAstSource(
            file.relativePath,
            content
          )
        );

        filesAnalyzed += 1;
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : String(error);

        warnings.push(
          `${file.relativePath}: ${message}`
        );
      }
    }

    return {
      analyzer: this.id,
      durationMs: Math.round(
        performance.now() - startedAt
      ),
      findings,
      warnings:
        warnings.length > 0 ? warnings : undefined,
      metadata: {
        filesAnalyzed,
        findings: findings.length,
        parser: 'typescript-compiler-api'
      }
    };
  }
}
