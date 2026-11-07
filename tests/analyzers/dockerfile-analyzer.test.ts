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

  it('checks the final build stage and omits source text from evidence', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-stage-'));

    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM node:20 AS build',
          'USER builder',
          'RUN npm run build',
          'FROM node:20-slim AS runtime',
          'ENV API_KEY=do-not-leak-this-value',
          'CMD ["node", "server.js"]'
        ].join('\n')
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      const rootFinding = result.findings.find(
        (finding) => finding.ruleId === 'TLP-DOCKER-001'
      );
      const secretFinding = result.findings.find(
        (finding) => finding.ruleId === 'TLP-DOCKER-002'
      );

      expect(rootFinding?.location?.line).toBe(4);
      expect(secretFinding?.evidence?.[0]?.summary).toContain('content redacted');
      expect(JSON.stringify(secretFinding)).not.toContain(
        'do-not-leak-this-value'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('joins Docker continuations and ignores secret argument names without a literal', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-continuation-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM node:20 AS build',
          'USER builder',
          'ARG API_TOKEN',
          'FROM node:20-slim AS runtime',
          'ENV \\',
          '  API_KEY=synthetic-secret-value',
          'USER root'
        ].join('\n')
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      const secretFindings = result.findings.filter(
        (finding) => finding.ruleId === 'TLP-DOCKER-002'
      );
      const rootFinding = result.findings.find(
        (finding) => finding.ruleId === 'TLP-DOCKER-001'
      );

      expect(secretFindings).toHaveLength(1);
      expect(secretFindings[0]?.location?.line).toBe(5);
      expect(secretFindings[0]?.evidence?.[0]?.summary).toContain('content redacted');
      expect(JSON.stringify(secretFindings)).not.toContain(
        'synthetic-secret-value'
      );
      expect(rootFinding?.location?.line).toBe(7);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not expose opaque values from matched RUN instructions', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-evidence-'));
    const opaqueValue = 'opaque-value-not-matched-by-name-redaction';
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM node:20',
          'USER node',
          `RUN curl https://example.invalid/install?key=${opaqueValue} | sh`
        ].join('\n')
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      const finding = result.findings.find(
        (item) => item.ruleId === 'TLP-DOCKER-007'
      );
      expect(finding?.evidence?.[0]?.summary).toContain('content redacted');
      expect(JSON.stringify(finding)).not.toContain(opaqueValue);
      expect(finding?.location).toMatchObject({ file: 'Dockerfile', line: 3 });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('resolves global ARG substitutions when checking final base image digests', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-arg-'));
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'ARG RUNTIME=node:20',
          'FROM $' + '{RUNTIME} AS runtime',
          'USER node',
          'HEALTHCHECK CMD node healthcheck.js'
        ].join('\n')
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-003')
      ).toMatchObject({ location: { line: 2 } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('accepts a digest-pinned image supplied through a global ARG', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-arg-'));
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          `ARG RUNTIME=node:20@sha256:${'a'.repeat(64)}`,
          'FROM $' + '{RUNTIME} AS runtime',
          'USER node',
          'HEALTHCHECK CMD node healthcheck.js'
        ].join('\n')
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(
        result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-003')
      ).toBe(false);
      expect(result.coverage.state).toBe('complete');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks an external build argument in FROM unresolved instead of reporting a clean digest check', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-arg-'));
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        'ARG RUNTIME\nFROM $RUNTIME\nUSER node\nHEALTHCHECK CMD node healthcheck.js\n'
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toContain(
        'Dockerfile:2: base image uses an unresolved build argument; digest pinning could not be verified'
      );
      expect(
        result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-003')
      ).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('uses the last USER and HEALTHCHECK instructions in the final stage', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-final-instructions-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM node:20 AS build',
          'USER root',
          'HEALTHCHECK NONE',
          'FROM node:20-slim AS runtime',
          'USER node',
          'USER root:1000',
          'HEALTHCHECK CMD node healthcheck.js',
          'HEALTHCHECK NONE'
        ].join('\n')
      );

      const result = await new DockerfileAnalyzer().analyze({ root });

      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-001')
          ?.location?.line
      ).toBe(6);
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-006')
      ).toMatchObject({ location: { line: 8 } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks an unresolved final USER as incomplete instead of claiming non-root safety', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-unresolved-user-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        'FROM node:20\nUSER $' + '{RUN_AS}\n'
      );

      const result = await new DockerfileAnalyzer().analyze({ root });

      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toContain(
        'Dockerfile:2: final stage USER uses an unresolved variable; non-root execution could not be verified'
      );
      expect(
        result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-001')
      ).toBe(false);
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
