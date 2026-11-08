import { parentPort, workerData } from 'node:worker_threads';
import {
  analyzeAstSource,
  createAstProjectAnalysis,
  type AstProjectInput
} from './source-analysis.js';

if (!parentPort) throw new Error('AST project worker needs a parent port.');
if (!Array.isArray(workerData))
  throw new TypeError('AST project worker input is invalid.');

type AstWorkerMemoryStage =
  'inputs-received' | 'project-analysis-built' | 'file-analysis-complete';

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
const project = createAstProjectAnalysis(inputs);
reportMemory('project-analysis-built');
const findingsByPath: Array<[string, ReturnType<typeof analyzeAstSource>]> = [];
for (const input of inputs) {
  findingsByPath.push([
    input.filePath,
    analyzeAstSource(input.filePath, input.content, project)
  ]);
  // Findings and the cross-file flow summaries are plain result data. Once a
  // file has been analyzed, keep its AST only if the worker still needs it.
  // `scopes` and call-return maps use WeakMap keys, so deleting this strong
  // reference lets V8 collect that file's TypeScript nodes during large scans.
  project.sourceFiles.delete(input.filePath);
}
reportMemory('file-analysis-complete');
parentPort.postMessage({
  type: 'complete',
  findingsByPath,
  dependencyDigests: [...project.dependencyDigests]
});
parentPort.close();
