import { parentPort, workerData } from 'node:worker_threads';
import {
  analyzeAstProjectByComponents,
  planAstProjectComponents,
  type AstProjectInput
} from './source-analysis.js';

if (!parentPort) throw new Error('AST project worker needs a parent port.');
const planOnly =
  !Array.isArray(workerData) &&
  workerData &&
  typeof workerData === 'object' &&
  (workerData as { mode?: unknown }).mode === 'plan';
const rawInputs = Array.isArray(workerData)
  ? workerData
  : planOnly && Array.isArray((workerData as { inputs?: unknown }).inputs)
    ? (workerData as { inputs: unknown[] }).inputs
    : undefined;
if (!rawInputs) throw new TypeError('AST project worker input is invalid.');

type AstWorkerMemoryStage =
  'inputs-received' | 'component-plan-complete' | 'component-analysis-complete';

function reportMemory(stage: AstWorkerMemoryStage): void {
  if (process.env.TOOLIP_BENCHMARK_AST_MEMORY !== 'true') return;
  const memory = process.memoryUsage();
  parentPort?.postMessage({
    type: 'memory',
    stage,
    heapUsedBytes: memory.heapUsed,
    externalBytes: memory.external,
    arrayBuffersBytes: memory.arrayBuffers,
    rssBytes: memory.rss
  });
}

const inputs = rawInputs as AstProjectInput[];
parentPort.postMessage({ type: 'started' });
reportMemory('inputs-received');
if (planOnly) {
  const plan = planAstProjectComponents(inputs);
  parentPort.postMessage({
    type: 'plan',
    components: plan.components,
    componentDigests: [...plan.componentDigests],
    dependencyDigests: [...plan.dependencyDigests],
    projectWide: plan.projectWide
  });
  reportMemory('component-plan-complete');
  parentPort.close();
} else {
  const analysis = analyzeAstProjectByComponents(inputs);
  reportMemory('component-analysis-complete');
  parentPort.postMessage({
    type: 'complete',
    findingsByPath: [...analysis.findingsByPath],
    dependencyDigests: [...analysis.dependencyDigests]
  });
  parentPort.close();
}
