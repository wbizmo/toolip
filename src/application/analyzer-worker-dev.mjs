// Worker bootstrap used ONLY when Toolip runs from TypeScript sources (tests,
// `tsx src/index.ts`). It registers tsx's ESM hooks in the worker thread, then
// loads the real worker entry. The published package runs compiled
// analyzer-worker.js and never loads this file.
import { register } from 'tsx/esm/api';

register();
await import('./analyzer-worker.ts');
