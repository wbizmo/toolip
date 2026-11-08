import { parentPort, workerData } from 'node:worker_threads';
import {
  analyzeAstProjectByComponents,
  type AstProjectInput
} from './source-analysis.js';

if (!parentPort) throw new Error('AST project worker needs a parent port.');
if (!Array.isArray(workerData))
  throw new TypeError('AST project worker input is invalid.');

type AstWorkerMemoryStage = 'inputs-received' | 'component-analysis-complete';

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

const inputs = workerData as AstProjectInput[];
parentPort.postMessage({ type: 'started' });
reportMemory('inputs-received');
const analysis = analyzeAstProjectByComponents(inputs);
reportMemory('component-analysis-complete');
parentPort.postMessage({
  type: 'complete',
  findingsByPath: [...analysis.findingsByPath],
  dependencyDigests: [...analysis.dependencyDigests]
});
parentPort.close();
