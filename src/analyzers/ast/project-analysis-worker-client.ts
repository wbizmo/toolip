import { isMainThread, Worker } from 'node:worker_threads';
import type { Finding } from '../../contracts/finding.js';
import {
  analyzeAstProjectByComponents,
  planAstProjectComponents,
  type AstProjectComponentPlan,
  type AstProjectInput
} from './source-analysis.js';

export type AstProjectWorkerResult = Readonly<{
  findingsByPath: ReadonlyMap<string, readonly Finding[]>;
  componentDigests: ReadonlyMap<string, string>;
  dependencyDigests: ReadonlyMap<string, string>;
}>;

type WorkerMessage =
  | { type: 'started' }
  | {
      type: 'plan';
      components: string[][];
      componentDigests: Array<[string, string]>;
      dependencyDigests: Array<[string, string]>;
      projectWide: boolean;
    }
  | {
      type: 'memory';
      stage:
        | 'inputs-received'
        | 'component-plan-complete'
        | 'component-analysis-complete';
      heapUsedBytes: number;
      externalBytes: number;
      arrayBuffersBytes: number;
      rssBytes: number;
    }
  | {
      type: 'complete';
      findingsByPath: Array<[string, Finding[]]>;
      componentDigests: Array<[string, string]>;
      dependencyDigests: Array<[string, string]>;
    };

function abortError(message: string): Error {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

function timeoutError(message: string): Error {
  const error = new Error(message);
  error.name = 'TimeoutError';
  return error;
}

function analyzeInline(
  inputs: readonly AstProjectInput[]
): AstProjectWorkerResult {
  const analysis = analyzeAstProjectByComponents(inputs);
  return {
    findingsByPath: analysis.findingsByPath,
    componentDigests: analysis.componentDigests,
    dependencyDigests: analysis.dependencyDigests
  };
}

function isCompleteMessage(
  value: unknown
): value is Extract<WorkerMessage, { type: 'complete' }> {
  if (!value || typeof value !== 'object') return false;
  const message = value as Partial<
    Extract<WorkerMessage, { type: 'complete' }>
  >;
  return (
    message.type === 'complete' &&
    Array.isArray(message.findingsByPath) &&
    Array.isArray(message.componentDigests) &&
    Array.isArray(message.dependencyDigests)
  );
}

function isPlanMessage(
  value: unknown
): value is Extract<WorkerMessage, { type: 'plan' }> {
  if (!value || typeof value !== 'object') return false;
  const message = value as Partial<Extract<WorkerMessage, { type: 'plan' }>>;
  return (
    message.type === 'plan' &&
    Array.isArray(message.components) &&
    Array.isArray(message.componentDigests) &&
    Array.isArray(message.dependencyDigests) &&
    typeof message.projectWide === 'boolean'
  );
}

/** Build a bounded import-component plan in a killable worker. */
export async function planAstProjectInWorker(
  inputs: readonly AstProjectInput[],
  options: {
    signal?: AbortSignal;
    timeoutMs?: number;
    onWorkerStarted?: () => void;
  } = {}
): Promise<AstProjectComponentPlan> {
  if (options.signal?.aborted)
    throw abortError('AST project planning was cancelled.');
  if (!isMainThread) {
    const plan = planAstProjectComponents(inputs);
    if (options.signal?.aborted)
      throw abortError('AST project planning was cancelled.');
    return plan;
  }
  const timeoutMs = options.timeoutMs ?? 60_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000)
    throw new RangeError(
      'AST project worker timeout is outside the supported range.'
    );
  const extension = import.meta.url.endsWith('.ts') ? 'ts' : 'js';
  const worker = new Worker(
    new URL(
      extension === 'ts'
        ? './project-analysis-worker-bootstrap.mjs'
        : `./project-analysis-worker.${extension}`,
      import.meta.url
    ),
    {
      workerData: { mode: 'plan', inputs },
      ...(extension === 'ts' ? { execArgv: [] } : {}),
      resourceLimits: {
        maxOldGenerationSizeMb: 1024,
        maxYoungGenerationSizeMb: 128,
        stackSizeMb: 16
      }
    }
  );
  return new Promise<AstProjectComponentPlan>((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      stop(timeoutError('AST project planning exceeded its time budget.'));
    }, timeoutMs);
    const cleanup = (): void => {
      clearTimeout(timeout);
      options.signal?.removeEventListener('abort', onAbort);
      worker.removeAllListeners();
    };
    const stop = (error: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      void worker.terminate().then(
        () => reject(error),
        () => reject(error)
      );
    };
    const onAbort = (): void => {
      stop(abortError('AST project planning was cancelled.'));
    };
    worker.on('message', (message: WorkerMessage | unknown) => {
      if (settled) return;
      if (
        message &&
        typeof message === 'object' &&
        (message as { type?: unknown }).type === 'started'
      ) {
        options.onWorkerStarted?.();
        return;
      }
      if (
        message &&
        typeof message === 'object' &&
        (message as { type?: unknown }).type === 'memory'
      ) {
        const sample = message as Extract<WorkerMessage, { type: 'memory' }>;
        if (
          process.env.TOOLIP_BENCHMARK_AST_MEMORY === 'true' &&
          Number.isSafeInteger(sample.heapUsedBytes) &&
          Number.isSafeInteger(sample.externalBytes) &&
          Number.isSafeInteger(sample.arrayBuffersBytes) &&
          Number.isSafeInteger(sample.rssBytes)
        )
          process.stderr.write(`TOOLIP_AST_MEMORY ${JSON.stringify(sample)}\n`);
        return;
      }
      if (!isPlanMessage(message)) {
        stop(
          new Error('AST project worker returned an invalid component plan.')
        );
        return;
      }
      const expectedPaths = new Set(inputs.map((input) => input.filePath));
      const seenPaths = new Set<string>();
      let valid = true;
      for (const component of message.components) {
        if (!Array.isArray(component) || component.length === 0) {
          valid = false;
          break;
        }
        for (const filePath of component) {
          if (
            typeof filePath !== 'string' ||
            !expectedPaths.has(filePath) ||
            seenPaths.has(filePath)
          ) {
            valid = false;
            break;
          }
          seenPaths.add(filePath);
        }
      }
      const toDigestMap = (
        entries: Array<[string, string]>
      ): Map<string, string> | undefined => {
        const result = new Map<string, string>();
        for (const entry of entries) {
          if (
            !Array.isArray(entry) ||
            entry.length !== 2 ||
            typeof entry[0] !== 'string' ||
            !expectedPaths.has(entry[0]) ||
            result.has(entry[0]) ||
            typeof entry[1] !== 'string' ||
            !/^[a-f0-9]{64}$/u.test(entry[1])
          )
            return undefined;
          result.set(entry[0], entry[1]);
        }
        return result.size === expectedPaths.size ? result : undefined;
      };
      const componentDigests = toDigestMap(message.componentDigests);
      const dependencyDigests = toDigestMap(message.dependencyDigests);
      if (
        !valid ||
        seenPaths.size !== expectedPaths.size ||
        !componentDigests ||
        !dependencyDigests
      ) {
        stop(
          new Error('AST project worker returned inconsistent component data.')
        );
        return;
      }
      settled = true;
      cleanup();
      resolve({
        components: message.components,
        componentDigests,
        dependencyDigests,
        projectWide: message.projectWide
      });
    });
    worker.once('error', (error) => stop(error));
    worker.once('exit', (code) => {
      if (!settled)
        stop(
          new Error(`AST project worker exited before planning (code ${code}).`)
        );
    });
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
  });
}

/** Run synchronous TypeScript analysis in a killable, memory-bounded worker. */
export async function analyzeAstProjectInWorker(
  inputs: readonly AstProjectInput[],
  options: {
    signal?: AbortSignal;
    timeoutMs?: number;
    onWorkerStarted?: () => void;
  } = {}
): Promise<AstProjectWorkerResult> {
  if (options.signal?.aborted)
    throw abortError('AST project analysis was cancelled.');
  if (!isMainThread) {
    // AnalyzerRunner already owns this analyzer's killable worker. Avoid
    // creating a nested worker that could outlive the analyzer boundary.
    const result = analyzeInline(inputs);
    if (options.signal?.aborted)
      throw abortError('AST project analysis was cancelled.');
    return result;
  }

  const timeoutMs = options.timeoutMs ?? 60_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000)
    throw new RangeError(
      'AST project worker timeout is outside the supported range.'
    );
  const extension = import.meta.url.endsWith('.ts') ? 'ts' : 'js';
  const worker = new Worker(
    new URL(
      extension === 'ts'
        ? './project-analysis-worker-bootstrap.mjs'
        : `./project-analysis-worker.${extension}`,
      import.meta.url
    ),
    {
      workerData: inputs,
      ...(extension === 'ts' ? { execArgv: [] } : {}),
      resourceLimits: {
        maxOldGenerationSizeMb: 1024,
        maxYoungGenerationSizeMb: 128,
        stackSizeMb: 16
      }
    }
  );

  return new Promise<AstProjectWorkerResult>((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      stop(timeoutError('AST project analysis exceeded its time budget.'));
    }, timeoutMs);
    const cleanup = (): void => {
      clearTimeout(timeout);
      options.signal?.removeEventListener('abort', onAbort);
      worker.removeAllListeners();
    };
    const stop = (error: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      void worker.terminate().then(
        () => reject(error),
        () => reject(error)
      );
    };
    const onAbort = (): void => {
      stop(abortError('AST project analysis was cancelled.'));
    };
    worker.on('message', (message: WorkerMessage | unknown) => {
      if (settled) return;
      if (
        message &&
        typeof message === 'object' &&
        (message as { type?: unknown }).type === 'started'
      ) {
        options.onWorkerStarted?.();
        return;
      }
      if (
        message &&
        typeof message === 'object' &&
        (message as { type?: unknown }).type === 'memory'
      ) {
        const sample = message as Extract<WorkerMessage, { type: 'memory' }>;
        if (
          process.env.TOOLIP_BENCHMARK_AST_MEMORY === 'true' &&
          Number.isSafeInteger(sample.heapUsedBytes) &&
          Number.isSafeInteger(sample.externalBytes) &&
          Number.isSafeInteger(sample.arrayBuffersBytes) &&
          Number.isSafeInteger(sample.rssBytes)
        )
          process.stderr.write(`TOOLIP_AST_MEMORY ${JSON.stringify(sample)}\n`);
        return;
      }
      if (!isCompleteMessage(message)) {
        stop(new Error('AST project worker returned an invalid result.'));
        return;
      }
      const expectedPaths = new Set(inputs.map((input) => input.filePath));
      const findingsByPath = new Map<string, readonly Finding[]>();
      for (const entry of message.findingsByPath) {
        if (
          !Array.isArray(entry) ||
          typeof entry[0] !== 'string' ||
          !expectedPaths.has(entry[0]) ||
          findingsByPath.has(entry[0]) ||
          !Array.isArray(entry[1])
        ) {
          stop(
            new Error('AST project worker returned inconsistent file results.')
          );
          return;
        }
        findingsByPath.set(entry[0], entry[1]);
      }
      const dependencyDigests = new Map<string, string>();
      const componentDigests = new Map<string, string>();
      for (const entry of message.componentDigests) {
        if (
          !Array.isArray(entry) ||
          entry.length !== 2 ||
          typeof entry[0] !== 'string' ||
          !expectedPaths.has(entry[0]) ||
          componentDigests.has(entry[0]) ||
          typeof entry[1] !== 'string' ||
          !/^[a-f0-9]{64}$/u.test(entry[1])
        ) {
          stop(
            new Error('AST project worker returned invalid component digests.')
          );
          return;
        }
        componentDigests.set(entry[0], entry[1]);
      }
      for (const entry of message.dependencyDigests) {
        if (
          !Array.isArray(entry) ||
          typeof entry[0] !== 'string' ||
          !expectedPaths.has(entry[0]) ||
          dependencyDigests.has(entry[0]) ||
          typeof entry[1] !== 'string' ||
          !/^[a-f0-9]{64}$/u.test(entry[1])
        ) {
          stop(
            new Error('AST project worker returned invalid dependency digests.')
          );
          return;
        }
        dependencyDigests.set(entry[0], entry[1]);
      }
      if (
        findingsByPath.size !== expectedPaths.size ||
        componentDigests.size !== expectedPaths.size ||
        dependencyDigests.size !== expectedPaths.size
      ) {
        stop(new Error('AST project worker omitted files from its result.'));
        return;
      }
      settled = true;
      cleanup();
      resolve({ findingsByPath, componentDigests, dependencyDigests });
    });
    worker.once('error', (error) => stop(error));
    worker.once('exit', (code) => {
      if (!settled)
        stop(
          new Error(`AST project worker exited before results (code ${code}).`)
        );
    });
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
  });
}
