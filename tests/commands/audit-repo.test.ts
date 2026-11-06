import { Command } from 'commander';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { registerAuditRepoCommand } from '../../src/commands/audit-repo.js';
import { auditRemoteRepository } from '../../src/core/github/remote-audit.js';

vi.mock('../../src/core/github/remote-audit.js', () => ({
  auditRemoteRepository: vi.fn()
}));

describe('audit-repo command output', () => {
  afterEach(() => vi.restoreAllMocks());

  it('sanitizes report fingerprints before printing JSON', async () => {
    const rawFingerprint = 'a'.repeat(64);
    vi.mocked(auditRemoteRepository).mockResolvedValue({
      repository: 'https://github.com/example/project',
      report: {
        findings: [{ evidence: [{ fingerprint: rawFingerprint }] }],
        summary: { secrets: 1 }
      }
    } as never);
    const output: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((value) => {
      output.push(String(value));
    });
    const program = new Command();
    registerAuditRepoCommand(program);

    await program.parseAsync([
      'node',
      'toolip',
      'audit-repo',
      'https://github.com/example/project',
      '--json'
    ]);

    const serialized = output.join('\n');
    expect(serialized).not.toContain(rawFingerprint);
    expect(
      JSON.parse(serialized).report.findings[0].evidence[0].fingerprint
    ).toMatch(/^[a-f0-9]{64}$/);
  });
});
