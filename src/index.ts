#!/usr/bin/env node

import { createProgram } from './cli/program.js';
import { installRuntimeGuard } from './cli/runtime-guard.js';
import { handleError } from './utils/error-handler.js';

const program = createProgram();
installRuntimeGuard(program);
program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (error) {
  handleError(error);
}
