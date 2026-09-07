import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { createProgram } from '../../src/cli/program.js';

const expectedCommands = [
  'alternatives',
  'announce',
  'ast-scan',
  'audit-repo',
  'compare',
  'config',
  'dependency-confusion',
  'diff',
  'docker-scan',
  'doctor',
  'git-audit',
  'git-history',
  'history',
  'hook',
  'inspect',
  'install-scripts',
  'learn',
  'licenses',
  'mcp',
  'monorepo',
  'package-health',
  'pre-commit',
  'profile',
  'publish',
  'reachability',
  'sbom',
  'scan',
  'score',
  'self-test',
  'tree',
  'upgrade-pr',
  'vault',
  'vulnerabilities',
  'watch'
].sort();

describe('Toolip CLI composition', () => {
  it('builds the complete command tree with no duplicate top-level commands', () => {
    const program = createProgram();
    const names = program.commands.map((command) => command.name());

    expect([...names].sort()).toEqual(expectedCommands);
    expect(new Set(names).size).toBe(names.length);
  });

  it.each([
    ['vault', ['init', 'set', 'get', 'list', 'delete', 'export']],
    ['hook', ['install']]
  ] as const)('builds expected %s subcommands', (name, expected) => {
    const command = createProgram().commands.find((item) => item.name() === name);

    expect(command).toBeDefined();
    expect(command?.commands.map((item) => item.name()).sort())
      .toEqual([...expected].sort());
  });

  it('ships parser and MCP dependencies required by executable commands', async () => {
    const pkg = JSON.parse(await readFile('package.json', 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };

    expect(pkg.dependencies?.typescript).toBeDefined();
    expect(pkg.devDependencies?.typescript).toBeUndefined();
    expect(pkg.dependencies?.['@modelcontextprotocol/sdk']).toBeDefined();
  });
});
