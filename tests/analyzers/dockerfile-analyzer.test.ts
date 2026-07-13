import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DockerfileAnalyzer } from '../../src/analyzers/docker/analyzer.js';

describe('DockerfileAnalyzer', () => {
  it('detects root execution and secret-like ENV declarations', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-'));

    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        'FROM node:latest\nENV API_KEY=example\nCMD ["node","server.js"]\n'
      );

      const result = await new DockerfileAnalyzer().analyze({ root });

      expect(result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-001')).toBe(true);
      expect(result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-002')).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
