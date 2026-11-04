#!/usr/bin/env node

import { createProgram } from './cli/program.js';
import {
  assessNodeRuntime,
  decideRuntimeAccess,
  UNPATCHED_NODE_OVERRIDE
} from './core/runtime-check.js';
import { handleError } from './utils/error-handler.js';

const INFORMATIONAL = new Set(['--version', '-V', '--help', '-h', 'self-test']);

const runtime = decideRuntimeAccess(assessNodeRuntime(process.versions.node), {
  informational: process.argv.slice(2).some((arg) => INFORMATIONAL.has(arg)),
  override: process.env[UNPATCHED_NODE_OVERRIDE] === '1'
});

if (runtime.warning) {
  console.error(`Toolip warning: ${runtime.warning}`);
}

if (!runtime.allow) {
  console.error(`Toolip refused to run: ${runtime.error}`);
  process.exit(1);
}

const program = createProgram();
program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (error) {
  handleError(error);
}
