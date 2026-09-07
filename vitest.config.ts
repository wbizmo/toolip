import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: [
        'src/application/analyzer-runner.ts',
        'src/core/github/upgrade-pr.ts',
        'src/core/hooks.ts',
        'src/core/pre-commit.ts',
        'src/core/secret-utils.ts',
        'src/core/security-doctor.ts',
        'src/core/vault.ts',
        'src/mcp/workspace-boundary.ts'
      ],
      reporter: ['text', 'json-summary'],
      thresholds: {
        lines: 50,
        functions: 50,
        branches: 40,
        statements: 50
      }
    }
  }
});
