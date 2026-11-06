import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DockerfileAnalyzer } from '../../src/analyzers/docker/analyzer.js';

describe('DockerfileAnalyzer', () => {
  it('detects root execution and secret-like ENV declarations', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-'));

    try {
      const source =
        'FROM node:latest\nENV API_KEY=example\nCMD ["node","server.js"]\n';
      await writeFile(path.join(root, 'Dockerfile'), source);

      const result = await new DockerfileAnalyzer().analyze({ root });

      expect(
        result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-001')
      ).toBe(true);
      expect(
        result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-002')
      ).toBe(true);
      expect(result.findings[0]?.metadata?.sourceProvenance).toMatchObject({
        path: 'Dockerfile',
        sha256: createHash('sha256').update(source).digest('hex'),
        bytes: Buffer.byteLength(source),
        discoverySnapshot: { size: Buffer.byteLength(source) },
        readSnapshot: { size: Buffer.byteLength(source) }
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('reports the real location for repeated matching lines', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-'));

    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        'FROM node:latest\nENV API_KEY=example\nENV API_KEY=example\nUSER node\n'
      );

      const result = await new DockerfileAnalyzer().analyze({ root });
      const secrets = result.findings.filter(
        (finding) => finding.ruleId === 'TLP-DOCKER-002'
      );

      expect(secrets.map((finding) => finding.location?.line)).toEqual([2, 3]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('reports a changed Dockerfile as failed coverage when none were scanned', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-changed-')
    );

    try {
      await writeFile(path.join(root, 'Dockerfile'), 'FROM node:latest\n');

      const result = await new DockerfileAnalyzer(() => ({
        read: async () => ({ status: 'changed', bytes: 0 }),
        usage: { filesRead: 0, bytesRead: 0 }
      })).analyze({ root });

      expect(result.coverage).toMatchObject({
        state: 'failed',
        eligible: 1,
        scanned: 0,
        skipped: 1,
        failed: 0
      });
      expect(result.metadata).toMatchObject({
        eligibleDockerfiles: 1,
        dockerfiles: 0
      });
      expect(result.warnings).toEqual(['Dockerfile: skipped (changed)']);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('reports partial coverage when another Dockerfile was scanned', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-partial-')
    );

    try {
      await writeFile(path.join(root, 'Dockerfile'), 'FROM node:latest\n');
      await writeFile(
        path.join(root, 'Dockerfile.dev'),
        'FROM node:20\nUSER node\n'
      );

      const result = await new DockerfileAnalyzer(() => ({
        read: async (filePath) =>
          path.basename(filePath) === 'Dockerfile'
            ? { status: 'changed', bytes: 0 }
            : {
                status: 'ok',
                content: 'FROM node:20\nUSER node\n',
                bytes: 23
              },
        usage: { filesRead: 1, bytesRead: 23 }
      })).analyze({ root });

      expect(result.coverage).toMatchObject({
        state: 'partial',
        eligible: 2,
        scanned: 1,
        skipped: 1,
        failed: 0
      });
      expect(result.metadata).toMatchObject({
        eligibleDockerfiles: 2,
        dockerfiles: 1
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
