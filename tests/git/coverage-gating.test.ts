import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Command } from 'commander';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { registerDoctorCommand } from '../../src/commands/doctor.js';
import { registerPreCommitCommand } from '../../src/commands/pre-commit.js';
import { EXIT_CODES } from '../../src/application/exit-codes.js';
import { createReport } from '../../src/core/report.js';
import { renderMarkdownReport } from '../../src/core/report-writer.js';
import { runPreCommit } from '../../src/core/pre-commit.js';
import { runSecurityDoctor } from '../../src/core/security-doctor.js';
import { createScannerContext } from '../../src/core/scanner-context.js';
import {
  cleanupRepos,
  fakeSecretLine,
  git,
  makeRepo,
  write
} from '../helpers/git-repo.js';

let stdout: string[] = [];

beforeEach(() => {
  stdout = [];
  process.exitCode = undefined;
  vi.spyOn(console, 'log').mockImplementation(
    (...a) => void stdout.push(a.join(' '))
  );
  vi.spyOn(console, 'error').mockImplementation(
    (...a) => void stdout.push(a.join(' '))
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
  cleanupRepos();
});

const CLEAN = 'export const value = 1;\n';
const oversized = () =>
  JSON.stringify({ pad: 'x'.repeat(2 * 1024 * 1024 + 16) });

async function cli(
  register: (p: Command) => void,
  name: string,
  ...args: string[]
) {
  const program = new Command();
  program.exitOverride();
  register(program);
  await program.parseAsync(['node', 'toolip', name, ...args]);
  const code = Number(process.exitCode ?? 0);
  process.exitCode = undefined;
  return { code, out: stdout.join('\n') };
}

// Issue #27: partial scans used to pass if they had no high/critical findings.
describe('pre-commit fails closed on incomplete scans (issue #27)', () => {
  it('rejects an oversized eligible staged file even with zero findings', async () => {
    const root = makeRepo();
    write(root, 'big.json', oversized());
    git(root, 'add', 'big.json');

    const result = await runPreCommit(root);

    expect(result.findings).toEqual([]); // a zero-finding partial run…
    expect(result.coverage.state).toBe('failed'); // …no eligible file could be scanned
    expect(result.passed).toBe(false); // …is not an all-clear
    expect(result.blockedByIncompleteScan).toBe(true);
    expect(result.coverage).toMatchObject({
      eligible: 1,
      scanned: 0,
      skipped: 1
    });
  }, 30_000);

  it('rejects a binary eligible file and reports partial coverage next to scanned files', async () => {
    const root = makeRepo();
    write(root, 'ok.ts', CLEAN);
    write(root, 'data.txt', 'abc\u0000def');
    git(root, 'add', '-A');

    const result = await runPreCommit(root);

    expect(result.coverage).toMatchObject({
      state: 'partial',
      eligible: 2,
      scanned: 1,
      skipped: 1
    });
    expect(result.passed).toBe(false);
    expect(result.blockedByIncompleteScan).toBe(true);
  }, 30_000);

  it('does not block staged binary assets that the content reader confirms as binary', async () => {
    const root = makeRepo();
    const binary = Buffer.from([0, 0x42, 0x5a, 0x68, 0x00]);
    for (const name of ['archive.bz2', 'clip.mov', 'bundle.xz']) {
      writeFileSync(path.join(root, name), binary);
    }
    git(root, 'add', '-A');

    const result = await runPreCommit(root);

    expect(result.passed).toBe(true);
    expect(result.blockedByIncompleteScan).toBe(false);
    expect(result.coverage).toMatchObject({
      state: 'complete',
      eligible: 0,
      scanned: 0,
      skipped: 0
    });
  }, 30_000);

  it('cannot opt eligible staged files out of fail-closed coverage', async () => {
    const root = makeRepo();
    write(root, 'ok.ts', CLEAN);
    write(root, 'big.json', oversized());
    git(root, 'add', '-A');

    const result = await runPreCommit(root, { failOnIncomplete: false });

    expect(result.passed).toBe(false);
    expect(result.coverage.state).toBe('partial');
    expect(result.blockedByIncompleteScan).toBe(true);

    // Explicit full scans retain the opt-out for partial coverage.
    const full = await runPreCommit(root, {
      full: true,
      failOnIncomplete: false
    });
    expect(full.coverage.state).toBe('partial');
    // The full-scan coverage opt-out does not override unrelated findings.
    expect(full.blockedByIncompleteScan).toBe(false);
    expect(full.passed).toBe(full.summary.blocking === 0);

    // …but nothing-scanned cannot be opted out of.
    const nothing = makeRepo();
    write(nothing, 'big.json', oversized());
    git(nothing, 'add', '-A');
    expect(
      (await runPreCommit(nothing, { failOnIncomplete: false })).passed
    ).toBe(false);
  });

  it('does not count conscious exclusions (.toolipignore, assets, symlinks) as incomplete', async () => {
    const root = makeRepo();
    write(root, '.toolipignore', 'generated\n');
    write(root, 'generated/huge.json', oversized());
    write(root, 'logo.png', 'png');
    write(root, 'ok.ts', CLEAN);
    git(root, 'add', '-A');

    const result = await runPreCommit(root);

    expect(result.coverage.state).toBe('complete');
    expect(result.passed).toBe(true);
  });

  it('honors --fail-on thresholds for complete scans', async () => {
    const root = makeRepo();
    // A medium-severity configuration finding (permissive CORS).
    write(root, 'server.ts', "app.use(cors({ origin: '*' }));\n");
    git(root, 'add', '-A');

    const base = await runPreCommit(root, { failOn: 'high' });
    const strict = await runPreCommit(root, { failOn: 'low' });
    const none = await runPreCommit(root, { failOn: 'none' });

    expect(none.passed).toBe(true);
    expect(base.passed).toBe(true);
    expect(strict.passed).toBe(false);
    expect(strict.summary.blocking).toBeGreaterThan(base.summary.blocking);
  });

  it('shows only findings meeting the selected CLI threshold', async () => {
    const root = makeRepo();
    write(root, 'server.ts', "app.use(cors({ origin: '*' }));\n");
    git(root, 'add', '-A');

    const strict = await cli(
      registerPreCommitCommand,
      'pre-commit',
      '--path',
      root,
      '--fail-on',
      'low',
      '--show-findings'
    );
    expect(strict.code).toBe(EXIT_CODES.error);
    expect(strict.out).toContain('Blocking Findings');

    stdout = [];
    const none = await cli(
      registerPreCommitCommand,
      'pre-commit',
      '--path',
      root,
      '--fail-on',
      'none',
      '--show-findings'
    );
    expect(none.code).toBe(0);
    expect(none.out).toContain('Blocking Findings: 0');
    expect(none.out).not.toContain('\nBlocking Findings\n');
  }, 20_000);

  it('keeps blocking on real findings and reports them rather than the incomplete reason', async () => {
    const root = makeRepo();
    write(root, 'leak.ts', fakeSecretLine('blocked'));
    write(root, 'big.json', oversized());
    git(root, 'add', '-A');

    const result = await runPreCommit(root);

    expect(result.passed).toBe(false);
    expect(result.summary.blocking).toBeGreaterThan(0);
    expect(result.blockedByIncompleteScan).toBe(false);
  });

  it('returns the incomplete code over a blocking-finding code', async () => {
    const root = makeRepo();
    write(root, 'leak.ts', fakeSecretLine('mixed'));
    write(root, 'big.json', oversized());
    git(root, 'add', '-A');

    const result = await runPreCommit(root);
    expect(result.summary.blocking).toBeGreaterThan(0);
    expect(result.coverage.state).toBe('partial');
    expect(
      (await cli(registerPreCommitCommand, 'pre-commit', '--path', root)).code
    ).toBe(EXIT_CODES.incomplete);
    expect(
      (
        await cli(
          registerPreCommitCommand,
          'pre-commit',
          '--path',
          root,
          '--no-fail-on-incomplete'
        )
      ).code
    ).toBe(EXIT_CODES.incomplete);
  });

  it('exposes distinct exit codes on the CLI: 4 nothing scanned, 3 partial, 1 findings, 0 complete', async () => {
    const nothing = makeRepo();
    write(nothing, 'big.json', oversized());
    git(nothing, 'add', '-A');
    expect(
      (await cli(registerPreCommitCommand, 'pre-commit', '--path', nothing))
        .code
    ).toBe(EXIT_CODES.failed);
    // The opt-out never lets a scan with no verified input pass.
    expect(
      (
        await cli(
          registerPreCommitCommand,
          'pre-commit',
          '--path',
          nothing,
          '--no-fail-on-incomplete'
        )
      ).code
    ).toBe(EXIT_CODES.failed);

    const partial = makeRepo();
    write(partial, 'ok.ts', CLEAN);
    write(partial, 'big.json', oversized());
    git(partial, 'add', '-A');
    expect(
      (await cli(registerPreCommitCommand, 'pre-commit', '--path', partial))
        .code
    ).toBe(EXIT_CODES.incomplete);

    const findings = makeRepo();
    write(findings, 'leak.ts', fakeSecretLine('cli'));
    git(findings, 'add', '-A');
    expect(
      (await cli(registerPreCommitCommand, 'pre-commit', '--path', findings))
        .code
    ).toBe(EXIT_CODES.error);

    const clean = makeRepo();
    write(clean, 'ok.ts', CLEAN);
    git(clean, 'add', '-A');
    const { code, out } = await cli(
      registerPreCommitCommand,
      'pre-commit',
      '--path',
      clean
    );
    expect(code).toBe(0);
    expect(out).toContain('COMPLETE');

    const optOut = await cli(
      registerPreCommitCommand,
      'pre-commit',
      '--path',
      partial,
      '--no-fail-on-incomplete'
    );
    expect(optOut.code).toBe(EXIT_CODES.incomplete);
    expect(optOut.out).toContain('PARTIAL');
  }, 20_000);

  it('rejects a bad --fail-on value', async () => {
    const root = makeRepo();
    await expect(
      cli(
        registerPreCommitCommand,
        'pre-commit',
        '--path',
        root,
        '--fail-on',
        'urgent'
      )
    ).rejects.toMatchObject({ code: 'INVALID_FAIL_ON' });
  });
});

describe('doctor coverage covers I/O failures, caps and cancellation (issue #27)', () => {
  async function doctorContext(files: Record<string, string>) {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'toolip-doctor-cov-'));
    for (const [name, body] of Object.entries(files))
      writeFileSync(path.join(dir, name), body);
    return { dir, context: await createScannerContext(dir) };
  }

  it('a complete run reports totals', async () => {
    const { dir, context } = await doctorContext({
      'a.ts': CLEAN,
      'b.ts': CLEAN,
      'notes.md': '# hi'
    });
    try {
      const result = await runSecurityDoctor(context);
      expect(result.coverage).toMatchObject({
        state: 'complete',
        eligible: 3,
        scanned: 3,
        skipped: 0,
        failed: 0
      });
      expect(result.coverage.excluded).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it('an I/O failure makes the run partial with a failed count', async () => {
    const { dir, context } = await doctorContext({
      'a.ts': CLEAN,
      'b.ts': CLEAN
    });
    try {
      let calls = 0;
      const result = await runSecurityDoctor(context, {
        contentProvider: async () => {
          calls += 1;
          return calls === 1
            ? { status: 'ok', content: CLEAN, bytes: CLEAN.length }
            : { status: 'failed', bytes: 0, error: 'EIO: i/o error' };
        }
      });
      expect(result.coverage).toMatchObject({
        state: 'partial',
        eligible: 2,
        scanned: 1,
        failed: 1
      });
      expect(result.findings).toEqual([]); // zero findings, still not an all-clear
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the byte/file caps make the run partial', async () => {
    const { dir, context } = await doctorContext({
      'a.ts': CLEAN,
      'b.ts': CLEAN,
      'c.ts': CLEAN
    });
    try {
      const result = await runSecurityDoctor(context, {
        budget: { maxFiles: 1, maxFileBytes: 1024, maxTotalBytes: 1024 }
      });
      expect(result.coverage).toMatchObject({
        state: 'partial',
        eligible: 3,
        scanned: 1,
        skipped: 2
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('cancellation counts every remaining eligible file as unexamined', async () => {
    const { dir, context } = await doctorContext({
      'a.ts': CLEAN,
      'b.ts': CLEAN,
      'c.ts': CLEAN,
      'd.ts': CLEAN
    });
    try {
      const controller = new AbortController();
      controller.abort();
      const result = await runSecurityDoctor(context, {
        signal: controller.signal
      });
      expect(result.coverage.state).toBe('failed');
      expect(result.coverage.eligible).toBe(4);
      expect(result.coverage.scanned).toBe(0);
      expect(result.coverage.skipped).toBe(4);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('reports and the doctor command expose analysis state (issue #27)', () => {
  it('a report with no findings but a partial analysis is not rendered as an all-clear', () => {
    const complete = renderMarkdownReport(
      createReport({
        version: '0',
        command: 'doctor',
        root: '/r',
        findings: [],
        analysis: { state: 'complete', reasons: [] }
      })
    );
    const partial = renderMarkdownReport(
      createReport({
        version: '0',
        command: 'doctor',
        root: '/r',
        findings: [],
        analysis: {
          state: 'partial',
          reasons: ['1 of 4 eligible input(s) were not analyzed']
        }
      })
    );

    expect(complete).toContain('No findings were detected.');
    expect(partial).not.toContain('No findings were detected.');
    expect(partial).toContain('not an all-clear');
    expect(partial).toContain('PARTIAL');
    expect(partial).toContain('1 of 4 eligible');
  });

  it('JSON reports carry the analysis block', () => {
    const report = createReport({
      version: '0',
      command: 'scan',
      root: '/r',
      findings: [],
      analysis: { state: 'failed', reasons: ['git safety: failed'] }
    });
    expect(report.analysis).toEqual({
      state: 'failed',
      reasons: ['git safety: failed']
    });
    expect(
      createReport({ version: '0', command: 'x', root: '/r', findings: [] })
        .analysis
    ).toBeUndefined();
  });

  it('doctor exits 3 on a partial run with --fail-on-incomplete, and 2 on findings with --fail-on', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'toolip-doctor-cli-'));
    try {
      writeFileSync(path.join(dir, 'package.json'), '{}');
      writeFileSync(path.join(dir, 'big.json'), oversized());

      const partial = await cli(registerDoctorCommand, 'doctor', '--path', dir);
      expect(partial.code).toBe(0); // default stays compatible…
      expect(partial.out).toContain('PARTIAL'); // …but is never silent

      expect(
        (
          await cli(
            registerDoctorCommand,
            'doctor',
            '--path',
            dir,
            '--fail-on-incomplete'
          )
        ).code
      ).toBe(EXIT_CODES.incomplete);

      writeFileSync(path.join(dir, 'big.json'), '{}');
      writeFileSync(path.join(dir, 'leak.ts'), fakeSecretLine('doctor'));
      expect(
        (
          await cli(
            registerDoctorCommand,
            'doctor',
            '--path',
            dir,
            '--fail-on',
            'high'
          )
        ).code
      ).toBe(EXIT_CODES.findings);
      expect(
        (await cli(registerDoctorCommand, 'doctor', '--path', dir)).code
      ).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
