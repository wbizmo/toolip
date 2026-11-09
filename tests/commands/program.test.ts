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
  'github-app',
  'history',
  'hook',
  'inspect',
  'install-scripts',
  'intelligence',
  'learn',
  'licenses',
  'mcp',
  'monorepo',
  'package-health',
  'policy',
  'pr-scan',
  'pre-commit',
  'profile',
  'publish',
  'report',
  'reachability',
  'sbom',
  'scan',
  'score',
  'self-test',
  'tree',
  'upgrade-pr',
  'vault',
  'vex',
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
    ['hook', ['install']],
    ['intelligence', ['snapshot']],
    ['sbom', ['verify']],
    ['vex', ['export', 'sign', 'validate']]
  ] as const)('builds expected %s subcommands', (name, expected) => {
    const command = createProgram().commands.find(
      (item) => item.name() === name
    );

    expect(command).toBeDefined();
    expect(command?.commands.map((item) => item.name()).sort()).toEqual(
      [...expected].sort()
    );
  });

  it('exposes the opt-in GitHub App webhook service entrypoint', () => {
    const command = createProgram().commands.find(
      (item) => item.name() === 'github-app'
    );
    expect(command?.commands.map((item) => item.name())).toEqual(['serve']);
  });

  it('exposes local advisory snapshot refresh and verify operations', () => {
    const command = createProgram().commands.find(
      (item) => item.name() === 'intelligence'
    );
    const snapshot = command?.commands.find(
      (item) => item.name() === 'snapshot'
    );

    expect(snapshot?.commands.map((item) => item.name()).sort()).toEqual([
      'refresh',
      'verify'
    ]);
    expect(
      snapshot?.commands
        .find((item) => item.name() === 'verify')
        ?.options.map((option) => option.long)
    ).toEqual(expect.arrayContaining(['--public-key', '--public-key-id']));
  });

  it('exposes explicit signer-ID pins on every advisory snapshot consumer', () => {
    for (const name of ['scan', 'vulnerabilities']) {
      const command = createProgram().commands.find(
        (item) => item.name() === name
      );
      expect(command?.options.map((option) => option.long)).toContain(
        '--snapshot-public-key-id'
      );
    }
    const vex = createProgram().commands.find((item) => item.name() === 'vex');
    expect(
      vex?.commands
        .find((item) => item.name() === 'export')
        ?.options.map((option) => option.long)
    ).toContain('--snapshot-public-key-id');
  });

  it('exposes report verification as a nested evidence command', () => {
    const command = createProgram().commands.find(
      (item) => item.name() === 'report'
    );
    expect(command?.commands.map((item) => item.name())).toEqual(['verify']);
  });

  it('exposes signed declarative rule-pack loading through doctor and scan', () => {
    for (const name of ['doctor', 'scan']) {
      const command = createProgram().commands.find(
        (item) => item.name() === name
      );
      const options = command?.options.map((option) => option.long);
      expect(options).toEqual(
        expect.arrayContaining([
          '--rule-pack',
          '--rule-pack-public-key',
          '--rule-pack-key-id',
          '--allow-unsigned-rule-pack'
        ])
      );
    }
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
