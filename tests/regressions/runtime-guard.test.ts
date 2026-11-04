import { Command } from 'commander';
import { describe, expect, it, vi } from 'vitest';
import { installRuntimeGuard } from '../../src/cli/runtime-guard.js';

type Harness = {
  program: Command;
  scan: ReturnType<typeof vi.fn>;
  selfTest: ReturnType<typeof vi.fn>;
  stderr: string[];
  exit: ReturnType<typeof vi.fn>;
};

function build(nodeVersion: string, env: NodeJS.ProcessEnv = {}): Harness {
  const scan = vi.fn();
  const selfTest = vi.fn();
  const stderr: string[] = [];
  const exit = vi.fn((code: number): never => {
    throw new Error(`exit:${code}`);
  });

  const program = new Command();
  program.version('0.0.0');
  program.exitOverride();
  program
    .command('scan')
    .option('-o, --output <file>')
    .option('--format <name>')
    .argument('[target]')
    .action(scan);
  program.command('self-test').action(selfTest);
  installRuntimeGuard(program, {
    nodeVersion,
    env,
    write: (message) => stderr.push(message),
    exit
  });
  return { program, scan, selfTest, stderr, exit };
}

const run = (h: Harness, ...args: string[]) =>
  h.program.parseAsync(['node', 'toolip', ...args]);

describe('runtime guard bypass regression (issue #92 review)', () => {
  // Each of these spells an exempt token as an option value or operand. The
  // previous argv-sniffing guard treated them as informational and ran the scan.
  it.each([
    [['scan', '-o', '--help']],
    [['scan', '-o', '-h']],
    [['scan', '--format', 'self-test']],
    [['scan', 'self-test']]
  ])('blocks %j on an unpatched runtime', async (args) => {
    const h = build('22.23.3');
    await expect(run(h, ...args)).rejects.toThrow('exit:1');
    expect(h.scan).not.toHaveBeenCalled();
    expect(h.stderr.join('\n')).toContain('Toolip refused to run');
  });

  it('never runs a scan for version flags that follow a subcommand', async () => {
    // Commander treats -V/--version as the root flag wherever it appears, so
    // these print the version and never reach the scan action.
    for (const args of [
      ['scan', '--output', '-V'],
      ['scan', '--format', '--version']
    ]) {
      const h = build('22.23.3');
      await expect(run(h, ...args)).rejects.toBeDefined();
      expect(h.scan).not.toHaveBeenCalled();
    }
  });

  it('still allows genuine help and version output, with a warning', async () => {
    for (const flag of ['--version', '--help', '-h']) {
      const h = build('24.22.0');
      await expect(run(h, flag)).rejects.toMatchObject({
        code: expect.stringMatching(/^commander\.(version|help|helpDisplayed)$/)
      });
      expect(h.scan).not.toHaveBeenCalled();
      expect(h.stderr.join('\n')).toContain('Toolip warning');
      expect(h.exit).not.toHaveBeenCalled();
    }
  });

  it('allows self-test only as its own command so it can report the failure', async () => {
    const h = build('22.23.3');
    await run(h, 'self-test');
    expect(h.selfTest).toHaveBeenCalledOnce();
  });

  it('allows commands on patched runtimes without noise', async () => {
    const h = build('24.22.2');
    await run(h, 'scan', '-o', 'out.json');
    expect(h.scan).toHaveBeenCalledOnce();
    expect(h.stderr).toEqual([]);
  });

  it('honors the explicit override but keeps warning', async () => {
    const h = build('22.23.3', { TOOLIP_ALLOW_UNPATCHED_NODE: '1' });
    await run(h, 'scan');
    expect(h.scan).toHaveBeenCalledOnce();
    expect(h.stderr.join('\n')).toContain('Toolip warning');
  });

  it('fails closed on unsupported majors and unparseable versions', async () => {
    for (const version of ['23.11.0', '25.0.0', 'garbage']) {
      const h = build(version);
      await expect(run(h, 'scan')).rejects.toThrow('exit:1');
      expect(h.scan).not.toHaveBeenCalled();
    }
  });
});
