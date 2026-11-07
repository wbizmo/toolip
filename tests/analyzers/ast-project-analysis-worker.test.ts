import { describe, expect, it } from 'vitest';
import { analyzeAstProjectInWorker } from '../../src/analyzers/ast/project-analysis-worker-client.js';
import {
  analyzeAstSource,
  createAstProjectAnalysis,
  type AstProjectInput
} from '../../src/analyzers/ast/source-analysis.js';

const inputs: AstProjectInput[] = [
  {
    filePath: 'src/entry.ts',
    absolutePath: '/tmp/toolip-ast-worker/src/entry.ts',
    content: 'import { run } from "./helper.js"; run(process.env.INPUT);'
  },
  {
    filePath: 'src/helper.ts',
    absolutePath: '/tmp/toolip-ast-worker/src/helper.ts',
    content:
      'import { exec } from "node:child_process"; export function run(input: string | undefined) { exec(input ?? ""); }'
  }
];

describe('killable AST project analysis', () => {
  it('matches inline findings and dependency digests for the immutable inputs', async () => {
    const inline = createAstProjectAnalysis(inputs);
    const expectedFindings = new Map(
      inputs.map((input) => [
        input.filePath,
        analyzeAstSource(input.filePath, input.content, inline)
      ])
    );

    const workerResult = await analyzeAstProjectInWorker(inputs, {
      timeoutMs: 20_000
    });
    expect([...workerResult.findingsByPath]).toEqual([...expectedFindings]);
    expect([...workerResult.dependencyDigests]).toEqual([
      ...inline.dependencyDigests
    ]);
  }, 25_000);

  it('terminates synchronous TypeScript work when its caller aborts', async () => {
    const controller = new AbortController();
    let markWorkerStarted!: () => void;
    const workerStarted = new Promise<void>((resolve) => {
      markWorkerStarted = resolve;
    });
    const largeInput: AstProjectInput[] = [
      {
        filePath: 'src/large.ts',
        absolutePath: '/tmp/toolip-ast-worker/src/large.ts',
        content: 'const value = 1;\n'.repeat(100_000)
      }
    ];
    const analysis = analyzeAstProjectInWorker(largeInput, {
      signal: controller.signal,
      timeoutMs: 20_000,
      onWorkerStarted: () => {
        markWorkerStarted();
        controller.abort();
      }
    });

    await workerStarted;
    await expect(analysis).rejects.toMatchObject({ name: 'AbortError' });
  }, 25_000);
});
