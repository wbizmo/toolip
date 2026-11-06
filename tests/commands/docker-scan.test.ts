import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Command } from 'commander';
import { coverageOf } from '../../src/contracts/analysis.js';
import type { Analyzer } from '../../src/contracts/analyzer.js';
import { registerDockerScanCommand } from '../../src/commands/docker-scan.js';
import { afterEach, describe, expect, it, vi } from 'vitest';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

describe('docker-scan command', () => {
  it('reports failed coverage in JSON and sets the incomplete exit code', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-command-')
    );
    roots.push(root);
    const priorExitCode = process.exitCode;
    const output: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation((value) => {
      output.push(String(value));
    });
    const analyzer: Analyzer = {
      id: 'dockerfile-security',
      version: '1.0.0',
      analyze: async () => ({
        analyzer: 'dockerfile-security',
        durationMs: 0,
        findings: [],
        warnings: ['Dockerfile: skipped (changed)'],
        coverage: coverageOf({
          eligible: 1,
          scanned: 0,
          skipped: 1,
          failed: 0
        }),
        metadata: { eligibleDockerfiles: 1, dockerfiles: 0 }
      })
    };
    const program = new Command();
    registerDockerScanCommand(program, { analyzer });

    try {
      await program.parseAsync([
        'node',
        'toolip',
        'docker-scan',
        '--path',
        root,
        '--json'
      ]);

      const result = JSON.parse(output.join('\n')) as {
        analysis: { state: string; complete: boolean };
        summary: { dockerfiles: number };
      };
      expect(result.analysis).toMatchObject({
        state: 'failed',
        complete: false
      });
      expect(result.summary.dockerfiles).toBe(0);
      expect(process.exitCode).toBe(4);
    } finally {
      log.mockRestore();
      process.exitCode = priorExitCode;
    }
  });
});
