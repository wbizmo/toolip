import { register } from 'tsx/esm/api';

// Node 22 workers do not inherit tsx's .js-to-.ts resolver from `--import
// tsx`. Register the loader in the worker before importing the TypeScript
// worker entry point. Built packages launch the emitted .js entry directly.
register();
await import('./project-analysis-worker.ts');
