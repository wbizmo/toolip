import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // The host may report hundreds of CPUs while imposing a much smaller
    // process/thread budget. Bound file workers so process-level stress tests
    // and compiler workers can still run without EAGAIN or thread aborts.
    maxWorkers: 1,

    // Win32 v22 coverage instruments eight real Git fixture repositories
    // in one pre-existing test. Keep the default timeout everywhere else;
    // do not skip checks or alter the security scanner.
    testTimeout:
      process.platform === 'win32' &&
      process.versions.node.startsWith('22.') &&
      process.argv.includes('--coverage')
        ? 15_000
        : 5_000,
    coverage: {
      provider: 'v8',
      include: [
        'src/application/project-snapshot.ts',
        'src/application/task-scheduler.ts',
        'src/application/analyzer-runner.ts',
        'src/analyzers/malicious-content/analyzer.ts',
        'src/core/github/upgrade-pr.ts',
        'src/core/hooks.ts',
        'src/core/pre-commit.ts',
        'src/core/secret-utils.ts',
        'src/core/security-doctor.ts',
        'src/core/policy-as-code.ts',
        'src/core/rule-packs.ts',
        'src/core/pre-execution-gate.ts',
        'src/core/sarif.ts',
        'src/core/vault.ts',
        'src/mcp/workspace-boundary.ts'
      ],
      reporter: ['text', 'json-summary'],
      thresholds: {
        lines: 75,
        functions: 85,
        branches: 65,
        statements: 75
      }
    }
  }
});
