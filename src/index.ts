#!/usr/bin/env node

import { createProgram } from './cli/program.js';
import { handleError } from './utils/error-handler.js';

const program = createProgram();
program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (error) {
  handleError(error);
}
