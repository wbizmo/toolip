import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Command } from 'commander';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EXIT_CODES } from '../../src/application/exit-codes.js';
import type { Analyzer, AnalyzerResult } from '../../src/contracts/analyzer.js';
import { coverageOf } from '../../src/contracts/analysis.js';
import type { Finding } from '../../src/contracts/finding.js';
import { registerAstScanCommand } from '../../src/commands/ast-scan.js';
import { registerInstallScriptsCommand } from '../../src/commands/install-scripts.js';
import { registerReachabilityCommand } from '../../src/commands/reachability.js';
import { registerVulnerabilitiesCommand } from '../../src/commands/vulnerabilities.js';

type Register = (
  program: Command,
  deps: { analyzer?: Analyzer; timeoutMs?: number }
) => void;

const commands: Array<{
  name: string;
  register: Register;
  cleanMessage: RegExp;
}> = [
  {
    name: 'ast-scan',
    register: registerAstScanCommand,
    cleanMessage: /No supported dangerous-code patterns/
  },
  {
    name: 'install-scripts',
    register: registerInstallScriptsCommand,
    cleanMessage: /No supported suspicious lifecycle-script/
  },
  {
    name: 'reachability',
    register: registerReachabilityCommand
  },
  {
    name: 'vulnerabilities',
    register: registerVulnerabilitiesCommand,
    cleanMessage: /No disclosed vulnerabilities matched/
  }
];

const high: Finding = {
  id: 'F1',
  ruleId: 'R1',
  title: 'High finding',
  category: 'test',
  severity: 'high',
  confidence: 'high',
  message: 'bad',
  source: 'test'
};

function analyzer(
  id: string,
  run: () => Promise<Partial<AnalyzerResult>>
): Analyzer {
  return {
    id,
    version: '1.0.0',
    analyze: async () => ({
      analyzer: id,
      durationMs: 0,
      findings: [],
      ...(await run())
    })
  };
}

let stdout: string[] = [];
let stderr: string[] = [];
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), 'toolip-cmd-'));
  writeFileSync(path.join(dir, 'package.json'), '{}');
  stdout = [];
  stderr = [];
  process.exitCode = undefined;
  vi.spyOn(console, 'log').mockImplementation(
    (...args) => void stdout.push(args.join(' '))
  );
  vi.spyOn(console, 'error').mockImplementation(
    (...args) => void stderr.push(args.join(' '))
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
  rmSync(dir, { recursive: true, force: true });
});

async function run(
  register: Register,
  name: string,
  deps: { analyzer?: Analyzer; timeoutMs?: number },
  ...extra: string[]
): Promise<{ code: number; out: string }> {
  const program = new Command();
  program.exitOverride();
  register(program, deps);
  await program.parseAsync(['node', 'toolip', name, '--path', dir, ...extra]);
  const code = Number(process.exitCode ?? 0);
  process.exitCode = undefined;
  return { code, out: stdout.join('\n') };
}

// Issue #35: failed/timed-out analyzers used to print a clean-success message and exit 0.
describe.each(commands)(
  '$name status and exit-code contract (issue #35)',
  ({ name, register, cleanMessage }) => {
    it('complete and clean: exit 0 and (where applicable) the clean message', async () => {
      const { code, out } = await run(register, name, {
        analyzer: analyzer('ok', async () => ({
          coverage: coverageOf({
            eligible: 2,
            scanned: 2,
            skipped: 0,
            failed: 0
          })
        }))
      });
      expect(code).toBe(EXIT_CODES.ok);
      if (cleanMessage) expect(out).toMatch(cleanMessage);
    });

    it('a thrown analyzer error exits 4 and never prints a clean message', async () => {
      const { code, out } = await run(register, name, {
        analyzer: analyzer('boom', async () => {
          throw new Error('analysis exploded');
        })
      });
      expect(code).toBe(EXIT_CODES.failed);
      if (cleanMessage) expect(out).not.toMatch(cleanMessage);
      expect(stderr.join('\n')).toContain('FAILED');
    });

    it('a timed-out analyzer exits 4 and never prints a clean message', async () => {
      const { code, out } = await run(register, name, {
        analyzer: analyzer('slow', () => new Promise(() => undefined)),
        timeoutMs: 40
      });
      expect(code).toBe(EXIT_CODES.failed);
      if (cleanMessage) expect(out).not.toMatch(cleanMessage);
    });

    it('JSON output exposes the failed state even though the findings array is empty', async () => {
      const { code, out } = await run(
        register,
        name,
        {
          analyzer: analyzer('boom', async () => {
            throw new Error('json failure');
          })
        },
        '--json'
      );
      const body = JSON.parse(out);
      expect(code).toBe(EXIT_CODES.failed);
      expect(body.analysis).toMatchObject({
        state: 'failed',
        complete: false,
        execution: 'failed'
      });
      expect(body.analysis.reason).toContain('json failure');
      expect([...(body.findings ?? [])]).toEqual([]);
    });

    it('a partial run exits 3 and is not described as clean; --no-fail-on-incomplete keeps the label but exits 0', async () => {
      const partial = analyzer('partial', async () => ({
        coverage: coverageOf({
          eligible: 4,
          scanned: 3,
          skipped: 1,
          failed: 0
        }),
        warnings: ['one file skipped (oversized)']
      }));

      const strict = await run(register, name, { analyzer: partial });
      expect(strict.code).toBe(EXIT_CODES.incomplete);
      if (cleanMessage) expect(strict.out).not.toMatch(cleanMessage);
      expect(stderr.join('\n')).toContain('PARTIAL');

      stderr = [];
      const lenient = await run(
        register,
        name,
        { analyzer: partial },
        '--no-fail-on-incomplete'
      );
      expect(lenient.code).toBe(EXIT_CODES.ok);
      if (cleanMessage) expect(lenient.out).not.toMatch(cleanMessage);
      expect(stderr.join('\n')).toContain('PARTIAL');
    });

    it('JSON output marks a partial run as incomplete', async () => {
      const { out } = await run(
        register,
        name,
        {
          analyzer: analyzer('partial', async () => ({
            coverage: coverageOf({
              eligible: 4,
              scanned: 3,
              skipped: 1,
              failed: 0
            })
          }))
        },
        '--json'
      );
      expect(JSON.parse(out).analysis).toMatchObject({
        state: 'partial',
        complete: false,
        eligible: 4,
        scanned: 3,
        skipped: 1
      });
    });
  }
);

describe.each(commands.filter((c) => c.name !== 'reachability'))(
  '$name --fail-on',
  ({ name, register }) => {
    it('exits 2 when a complete run has a finding at or above the threshold', async () => {
      const withFinding = analyzer('f', async () => ({ findings: [high] }));
      expect(
        (
          await run(
            register,
            name,
            { analyzer: withFinding },
            '--fail-on',
            'high'
          )
        ).code
      ).toBe(EXIT_CODES.findings);
      expect(
        (
          await run(
            register,
            name,
            { analyzer: withFinding },
            '--fail-on',
            'critical'
          )
        ).code
      ).toBe(EXIT_CODES.ok);
      expect(
        (
          await run(
            register,
            name,
            { analyzer: withFinding },
            '--fail-on',
            'none'
          )
        ).code
      ).toBe(EXIT_CODES.ok);
    });

    it('rejects an invalid threshold instead of silently disabling the gate', async () => {
      await expect(
        run(
          register,
          name,
          { analyzer: analyzer('f', async () => ({})) },
          '--fail-on',
          'urgent'
        )
      ).rejects.toMatchObject({ code: 'INVALID_FAIL_ON' });
    });
  }
);

describe('real analyzers report honest coverage', () => {
  it('install-scripts without installed dependencies is NOT reported as clean', async () => {
    writeFileSync(
      path.join(dir, 'package-lock.json'),
      JSON.stringify({
        name: 'x',
        lockfileVersion: 3,
        packages: {
          '': { name: 'x', version: '1.0.0', dependencies: { left: '1.0.0' } },
          'node_modules/left': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/left/-/left-1.0.0.tgz',
            integrity: `sha512-${'A'.repeat(86)}==`
          }
        }
      })
    );

    const { code, out } = await run(
      registerInstallScriptsCommand,
      'install-scripts',
      {}
    );
    expect(code).toBe(EXIT_CODES.failed); // nothing could be inspected
    expect(out).not.toMatch(/No supported suspicious lifecycle-script/);
    expect(out).toContain('not inspected');
  });

  it('ast-scan on a clean project is complete and exits 0', async () => {
    writeFileSync(path.join(dir, 'ok.ts'), 'export const a = 1;\n');
    const { code, out } = await run(registerAstScanCommand, 'ast-scan', {});
    expect(code).toBe(EXIT_CODES.ok);
    expect(out).toMatch(/No supported dangerous-code patterns/);
  });
});
