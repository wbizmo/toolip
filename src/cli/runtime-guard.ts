import type { Command } from 'commander';
import {
  assessNodeRuntime,
  decideRuntimeAccess,
  UNPATCHED_NODE_OVERRIDE
} from '../core/runtime-check.js';

export type RuntimeGuardOptions = {
  nodeVersion?: string;
  env?: NodeJS.ProcessEnv;
  write?: (message: string) => void;
  exit?: (code: number) => never;
};

/**
 * Enforces the patched-Node.js floor (issue #92) at the point where commands
 * actually execute, not by sniffing argv.
 *
 * Why not argv: option values can spell `--help`, `-h` or `self-test`
 * (`scan -o --help`), which would have exempted a real scan on an unpatched
 * runtime. Commander only invokes `preAction` hooks for real command actions;
 * help and version output never reach them, so they stay available and still
 * print the warning. `self-test` (a direct child of the root program) is the
 * only exempt action so it can report the failure. O(1) time and space.
 */
export function installRuntimeGuard(
  program: Command,
  options: RuntimeGuardOptions = {}
): void {
  const assessment = assessNodeRuntime(
    options.nodeVersion ?? process.versions.node
  );
  if (assessment.status === 'ok') return;

  const env = options.env ?? process.env;
  const write = options.write ?? ((message: string) => console.error(message));
  const exit = options.exit ?? ((code: number): never => process.exit(code));
  const override = env[UNPATCHED_NODE_OVERRIDE] === '1';

  const informational = decideRuntimeAccess(assessment, {
    informational: true,
    override
  });
  if (informational.warning) {
    write(`Toolip warning: ${informational.warning}`);
  }

  program.hook('preAction', (_root, actionCommand) => {
    if (
      actionCommand.name() === 'self-test' &&
      actionCommand.parent === program
    ) {
      return;
    }

    const decision = decideRuntimeAccess(assessment, {
      informational: false,
      override
    });
    if (!decision.allow) {
      write(`Toolip refused to run: ${decision.error}`);
      exit(1);
    }
  });
}
