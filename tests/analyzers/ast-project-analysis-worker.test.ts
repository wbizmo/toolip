import { describe, expect, it } from 'vitest';
import { analyzeAstProjectInWorker } from '../../src/analyzers/ast/project-analysis-worker-client.js';
import {
  analyzeAstProjectByComponents,
  analyzeAstSource,
  createAstProjectAnalysis,
  transitiveImportDigests,
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
  },
  {
    filePath: 'src/standalone.ts',
    absolutePath: '/tmp/toolip-ast-worker/src/standalone.ts',
    content: 'export const safeValue = 42;'
  }
];

describe('killable AST project analysis', () => {
  it('keeps unrelated files out of the same TypeScript Program', () => {
    const unrelated: AstProjectInput[] = Array.from(
      { length: 128 },
      (_, index) => ({
        filePath: `src/independent-${index}.ts`,
        absolutePath: `/tmp/toolip-ast-independent/src/independent-${index}.ts`,
        content: `export const value${index} = ${index};`
      })
    );
    const analysis = analyzeAstProjectByComponents(unrelated);

    expect(analysis.componentCount).toBe(unrelated.length);
    expect(analysis.largestComponentFiles).toBe(1);
    expect(analysis.findingsByPath.size).toBe(unrelated.length);
    expect(analysis.dependencyDigests.size).toBe(unrelated.length);
  });

  it('keeps ambient declarations in a project-wide symbol environment', () => {
    const ambientInputs: AstProjectInput[] = [
      {
        filePath: 'src/a.ts',
        absolutePath: '/tmp/toolip-ast-ambient/src/a.ts',
        content: 'export const a = 1;'
      },
      {
        filePath: 'src/b.ts',
        absolutePath: '/tmp/toolip-ast-ambient/src/b.ts',
        content: 'export const b = 2;'
      },
      {
        filePath: 'src/globals.d.ts',
        absolutePath: '/tmp/toolip-ast-ambient/src/globals.d.ts',
        content: 'interface GlobalFixture { value: string }'
      }
    ];
    const analysis = analyzeAstProjectByComponents(ambientInputs);
    expect(analysis.componentCount).toBe(1);
    expect(analysis.largestComponentFiles).toBe(ambientInputs.length);
    expect(analysis.findingsByPath.size).toBe(ambientInputs.length);
  });

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

  it('preserves global results when connected and independent components mix', () => {
    const expected = createAstProjectAnalysis(inputs);
    const actual = analyzeAstProjectByComponents(inputs);
    expect([...actual.findingsByPath]).toEqual(
      inputs.map((input) => [
        input.filePath,
        analyzeAstSource(input.filePath, input.content, expected)
      ])
    );
    expect([...actual.dependencyDigests]).toEqual([
      ...expected.dependencyDigests
    ]);
    expect(actual.componentCount).toBe(2);
    expect(actual.largestComponentFiles).toBe(2);
  });

  it('resolves local imports across many indexed source directories', () => {
    const root = '/tmp/toolip-ast-many-directories';
    const directoryCount = 512;
    const imports = Array.from(
      { length: directoryCount },
      (_, index) =>
        `import { value as value${index} } from './modules/m${index}/helper.js';`
    ).join('\n');
    const inputs: AstProjectInput[] = [
      {
        filePath: 'src/entry.ts',
        absolutePath: `${root}/src/entry.ts`,
        content: imports
      },
      ...Array.from({ length: directoryCount }, (_, index) => ({
        filePath: `src/modules/m${index}/helper.ts`,
        absolutePath: `${root}/src/modules/m${index}/helper.ts`,
        content: `export const value = ${index};`
      }))
    ];

    const project = createAstProjectAnalysis(inputs);
    const changedProject = createAstProjectAnalysis(
      inputs.map((input) =>
        input.filePath === 'src/modules/m0/helper.ts'
          ? { ...input, content: 'export const value = 999;' }
          : input
      )
    );

    expect(project.sourceFiles.size).toBe(directoryCount + 1);
    expect(changedProject.dependencyDigests.get('src/entry.ts')).not.toBe(
      project.dependencyDigests.get('src/entry.ts')
    );
  });

  it('digests deep import graphs with linear visits and no recursive stack', () => {
    const vertexCount = 20_000;
    const inputs: AstProjectInput[] = Array.from(
      { length: vertexCount },
      (_, index) => ({
        filePath: `src/file-${String(index).padStart(5, '0')}.ts`,
        absolutePath: `/tmp/toolip-ast-deep-graph/src/file-${String(index).padStart(5, '0')}.ts`,
        content: `export const value = ${index};`
      })
    );
    const adjacency = new Map<string, ReadonlySet<string>>(
      inputs.map((input, index) => [
        input.filePath,
        index + 1 < vertexCount
          ? new Set([inputs[index + 1]?.filePath as string])
          : new Set<string>()
      ])
    );
    const stats = {
      vertexVisits: 0,
      edgeVisits: 0,
      peakDfsFrames: 0
    };

    const digests = transitiveImportDigests(inputs, adjacency, stats);

    expect(digests.size).toBe(vertexCount);
    expect(stats).toEqual({
      vertexVisits: vertexCount,
      edgeVisits: vertexCount - 1,
      peakDfsFrames: vertexCount
    });
    expect(digests.get(inputs[0]?.filePath ?? '')).not.toBe(
      digests.get(inputs.at(-1)?.filePath ?? '')
    );
  });

  it('keeps cyclic component digests stable across input ordering', () => {
    const inputs: AstProjectInput[] = ['a', 'b', 'c', 'd'].map((name) => ({
      filePath: `src/${name}.ts`,
      absolutePath: `/tmp/toolip-ast-cycle/src/${name}.ts`,
      content: `export const value = '${name}';`
    }));
    const adjacency = new Map<string, ReadonlySet<string>>([
      ['src/a.ts', new Set(['src/b.ts'])],
      ['src/b.ts', new Set(['src/a.ts', 'src/c.ts'])],
      ['src/c.ts', new Set(['src/d.ts'])],
      ['src/d.ts', new Set<string>()]
    ]);

    const forward = transitiveImportDigests(inputs, adjacency);
    const reversed = transitiveImportDigests(
      [...inputs].reverse(),
      new Map([...adjacency].reverse())
    );

    expect([...forward].sort()).toEqual([...reversed].sort());
    expect(forward.get('src/a.ts')).not.toBe(forward.get('src/b.ts'));
  });

  it('fails explicitly on source nesting beyond the AST depth budget', () => {
    const content = `export const value = ${'('.repeat(600)}1${')'.repeat(600)};`;

    expect(() =>
      createAstProjectAnalysis([
        {
          filePath: 'src/deep.ts',
          absolutePath: '/tmp/toolip-ast-deep-source/src/deep.ts',
          content
        }
      ])
    ).toThrow('AST source traversal budget exceeded');
  });

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
