import { readFile } from 'node:fs/promises';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import type { Finding } from '../../contracts/finding.js';
import { createScannerContext } from '../../core/scanner-context.js';
import { readNpmDependencyInventory } from '../../core/dependencies/inventory.js';
import {
  extractPackageImports,
  type ImportReference
} from './import-graph.js';

const codeExtensions = new Set([
  'js',
  'jsx',
  'ts',
  'tsx',
  'mjs',
  'cjs'
]);

export type PackageReachability = {
  packageName: string;
  state:
    | 'reachable'
    | 'possibly-reachable'
    | 'not-observed';
  direct: boolean;
  development: boolean;
  references: Array<
    ImportReference & {
      file: string;
    }
  >;
};

export class ReachabilityAnalyzer implements Analyzer {
  readonly id = 'package-reachability';
  readonly version = '1.0.0';

  async analyze(
    context: AnalyzerContext
  ): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const dependencies =
      await readNpmDependencyInventory(context.root);
    const scannerContext =
      await createScannerContext(context.root);

    const references = new Map<
      string,
      PackageReachability['references']
    >();

    for (const file of scannerContext.files) {
      if (
        !codeExtensions.has(file.extension) ||
        file.relativePath.endsWith('.d.ts') ||
        file.relativePath.startsWith('dist/')
      ) {
        continue;
      }

      if (context.signal?.aborted) {
        throw new Error(
          'Reachability analysis was cancelled.'
        );
      }

      const content = await readFile(
        file.absolutePath,
        'utf8'
      );

      for (const reference of extractPackageImports(
        file.relativePath,
        content
      )) {
        const current =
          references.get(reference.packageName) ?? [];

        current.push({
          ...reference,
          file: file.relativePath
        });

        references.set(reference.packageName, current);
      }
    }

    const packageStates = dependencies.map(
      (dependency): PackageReachability => {
        const packageReferences =
          references.get(dependency.name) ?? [];

        return {
          packageName: dependency.name,
          state:
            packageReferences.length > 0
              ? 'reachable'
              : dependency.direct
                ? 'possibly-reachable'
                : 'not-observed',
          direct: dependency.direct,
          development: dependency.development,
          references: packageReferences
        };
      }
    );

    const findings: Finding[] = packageStates
      .filter((item) => item.state === 'reachable')
      .map((item) => ({
        id: `TLP-REACH-${item.packageName
          .toUpperCase()
          .replaceAll(/[^A-Z0-9]/g, '-')}`,
        ruleId: 'TLP-REACH-001',
        title: `Package usage observed: ${item.packageName}`,
        category: 'reachability',
        severity: 'info',
        confidence: 'high',
        message:
          `${item.packageName} is imported or required by project source files.`,
        source: 'typescript-ast',
        evidence: item.references.slice(0, 20).map(
          (reference) => ({
            summary:
              `${reference.file}:${reference.line}:${reference.column} ` +
              `${reference.kind} import`,
            fingerprint:
              `${item.packageName}:${reference.file}:` +
              `${reference.line}:${reference.column}`
          })
        ),
        metadata: {
          package: item.packageName,
          state: item.state,
          direct: item.direct,
          development: item.development,
          references: item.references
        }
      }));

    return {
      analyzer: this.id,
      durationMs: Math.round(
        performance.now() - startedAt
      ),
      findings,
      metadata: {
        dependencies: packageStates.length,
        reachable: packageStates.filter(
          (item) => item.state === 'reachable'
        ).length,
        possiblyReachable: packageStates.filter(
          (item) =>
            item.state === 'possibly-reachable'
        ).length,
        notObserved: packageStates.filter(
          (item) => item.state === 'not-observed'
        ).length,
        packages: packageStates
      }
    };
  }
}
