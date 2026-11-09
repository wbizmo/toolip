import { describe, expect, it, vi } from 'vitest';
import {
  analyzeAstProjectInWorker,
  planAstProjectInWorker,
  getAstWorkerQueueMetrics
} from '../../src/analyzers/ast/project-analysis-worker-client.js';
import {
  analyzeAstProjectByComponents,
  analyzeAstSource,
  createAstProjectAnalysis,
  planAstProjectComponents,
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

  it('keeps a single script file inside the project checker fallback', () => {
    const scriptInput: AstProjectInput = {
      filePath: 'src/script.ts',
      absolutePath: '/tmp/toolip-ast-script/src/script.ts',
      content: 'const value = process.env.INPUT; eval(value);'
    };
    const project = createAstProjectAnalysis([scriptInput]);
    const expected = analyzeAstSource(
      scriptInput.filePath,
      scriptInput.content,
      project
    );
    const actual = analyzeAstProjectByComponents([scriptInput]);

    expect(actual.componentCount).toBe(1);
    expect(actual.findingsByPath.get(scriptInput.filePath)).toEqual(expected);
  });

  it('matches inline findings and dependency digests for the immutable inputs', async () => {
    const parityInputs: AstProjectInput[] = [
      ...inputs,
      {
        filePath: 'src/reassigned.ts',
        absolutePath: '/tmp/toolip-ast-worker/src/reassigned.ts',
        content:
          'import { exec } from "node:child_process"; let run = exec; run = (value: string) => value; run(untrusted);'
      },
      {
        filePath: 'src/before-write.ts',
        absolutePath: '/tmp/toolip-ast-worker/src/before-write.ts',
        content:
          'import { exec } from "node:child_process"; let run = exec; run(untrusted); run = (value: string) => value;'
      },
      {
        filePath: 'src/conditional-write.ts',
        absolutePath: '/tmp/toolip-ast-worker/src/conditional-write.ts',
        content:
          'import { exec } from "node:child_process"; let run = (value: string) => value; if (condition) run = exec; run(untrusted);'
      },
      {
        filePath: 'src/reexport-route.ts',
        absolutePath: '/tmp/toolip-ast-worker/src/reexport-route.ts',
        content: 'import { run } from "./barrel.js"; run(untrusted);'
      },
      {
        filePath: 'src/barrel.ts',
        absolutePath: '/tmp/toolip-ast-worker/src/barrel.ts',
        content: 'export { run } from "./bridge.js";'
      },
      {
        filePath: 'src/bridge.ts',
        absolutePath: '/tmp/toolip-ast-worker/src/bridge.ts',
        content: 'export { exec as run } from "node:child_process";'
      },
      {
        filePath: 'src/commonjs-route.ts',
        absolutePath: '/tmp/toolip-ast-worker/src/commonjs-route.ts',
        content: 'import { run } from "./bridge.cjs"; run(untrusted);'
      },
      {
        filePath: 'src/bridge.cjs',
        absolutePath: '/tmp/toolip-ast-worker/src/bridge.cjs',
        content:
          'const cp = require("node:child_process"); exports.run = cp.exec;'
      }
    ];
    const inline = createAstProjectAnalysis(parityInputs);
    const expectedFindings = new Map(
      parityInputs.map((input) => [
        input.filePath,
        analyzeAstSource(input.filePath, input.content, inline)
      ])
    );

    const workerResult = await analyzeAstProjectInWorker(parityInputs, {
      timeoutMs: 20_000
    });
    expect([...workerResult.findingsByPath]).toEqual([...expectedFindings]);
    expect(workerResult.findingsByPath.get('src/reassigned.ts')).toEqual([]);
    expect(
      workerResult.findingsByPath
        .get('src/before-write.ts')
        ?.map((finding) => finding.ruleId)
    ).toContain('TLP-AST-003');
    expect(
      workerResult.findingsByPath
        .get('src/conditional-write.ts')
        ?.map((finding) => finding.ruleId)
    ).toContain('TLP-AST-011');
    expect(
      workerResult.findingsByPath
        .get('src/reexport-route.ts')
        ?.map((finding) => finding.ruleId)
    ).toContain('TLP-AST-003');
    expect(
      workerResult.findingsByPath
        .get('src/commonjs-route.ts')
        ?.map((finding) => finding.ruleId)
    ).toContain('TLP-AST-003');
    expect([...workerResult.componentDigests]).toEqual([
      ...planAstProjectComponents(parityInputs).componentDigests
    ]);
    expect([...workerResult.dependencyDigests]).toEqual([
      ...inline.dependencyDigests
    ]);
  }, 25_000);

  it('bounds process-wide AST workers, cancels queued work, and rejects excess queueing', async () => {
    const first = analyzeAstProjectInWorker(inputs, { timeoutMs: 20_000 });
    expect(getAstWorkerQueueMetrics()).toMatchObject({
      active: 1,
      queued: 0,
      maxActive: 1,
      maxQueued: 1
    });

    const controller = new AbortController();
    const queued = analyzeAstProjectInWorker(inputs, {
      signal: controller.signal,
      timeoutMs: 20_000
    });
    expect(getAstWorkerQueueMetrics()).toMatchObject({ active: 1, queued: 1 });
    await expect(
      analyzeAstProjectInWorker(inputs, { timeoutMs: 20_000 })
    ).rejects.toMatchObject({ name: 'CapacityError' });

    controller.abort();
    await expect(queued).rejects.toMatchObject({ name: 'AbortError' });
    expect(getAstWorkerQueueMetrics()).toMatchObject({ active: 1, queued: 0 });
    await expect(first).resolves.toHaveProperty('findingsByPath');
    expect(getAstWorkerQueueMetrics()).toMatchObject({ active: 0, queued: 0 });
  }, 30_000);

  it('matches inline import-component plans in the bounded worker', async () => {
    const expected = planAstProjectComponents(inputs);
    const actual = await planAstProjectInWorker(inputs, {
      timeoutMs: 20_000
    });

    expect(actual.components).toEqual(expected.components);
    expect([...actual.componentDigests]).toEqual([
      ...expected.componentDigests
    ]);
    expect([...actual.dependencyDigests]).toEqual([
      ...expected.dependencyDigests
    ]);
    expect(actual.projectWide).toBe(expected.projectWide);
  }, 25_000);

  it('accepts optional worker memory samples while planning components', async () => {
    vi.stubEnv('TOOLIP_BENCHMARK_AST_MEMORY', 'true');
    const stderrWrite = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    try {
      const actual = await planAstProjectInWorker(inputs, {
        timeoutMs: 20_000
      });
      expect(actual.components).toEqual(
        planAstProjectComponents(inputs).components
      );
      expect(stderrWrite).toHaveBeenCalled();
    } finally {
      stderrWrite.mockRestore();
      vi.unstubAllEnvs();
    }
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

  it('terminates component planning when its caller aborts', async () => {
    const controller = new AbortController();
    let markWorkerStarted!: () => void;
    const workerStarted = new Promise<void>((resolve) => {
      markWorkerStarted = resolve;
    });
    const largeInput: AstProjectInput[] = [
      {
        filePath: 'src/large.ts',
        absolutePath: '/tmp/toolip-ast-worker/src/large.ts',
        content: 'export const value = 1;\n'.repeat(100_000)
      }
    ];
    const planning = planAstProjectInWorker(largeInput, {
      signal: controller.signal,
      timeoutMs: 20_000,
      onWorkerStarted: () => {
        markWorkerStarted();
        controller.abort();
      }
    });

    await workerStarted;
    await expect(planning).rejects.toMatchObject({ name: 'AbortError' });
  }, 25_000);
});
