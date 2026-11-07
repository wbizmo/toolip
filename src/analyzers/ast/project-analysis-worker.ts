import { parentPort, workerData } from 'node:worker_threads';
import {
  analyzeAstSource,
  createAstProjectAnalysis,
  type AstProjectInput
} from './source-analysis.js';

if (!parentPort) throw new Error('AST project worker needs a parent port.');
if (!Array.isArray(workerData))
  throw new TypeError('AST project worker input is invalid.');

const inputs = workerData as AstProjectInput[];
parentPort.postMessage({ type: 'started' });
const project = createAstProjectAnalysis(inputs);
const findingsByPath = inputs.map((input) => [
  input.filePath,
  analyzeAstSource(input.filePath, input.content, project)
]);
parentPort.postMessage({
  type: 'complete',
  findingsByPath,
  dependencyDigests: [...project.dependencyDigests]
});
parentPort.close();
