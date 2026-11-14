import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DockerfileAnalyzer } from '../../src/analyzers/docker/analyzer.js';

describe('DockerfileAnalyzer', () => {
  it('distinguishes external unpinned COPY sources from local stages and digest-pinned sources', async () => {
    const digest = 'a'.repeat(64);
    const scenarios = [
      {
        body: 'COPY --from=example.invalid/build:latest /bin/tool /tool',
        line: 2,
        finding: true,
        incomplete: false
      },
      {
        body:
          'COPY --from=example.invalid/build@sha256:' +
          digest +
          ' /bin/tool /tool',
        finding: false,
        incomplete: false
      },
      {
        body: 'COPY --from=builder /bin/tool /tool',
        local: true,
        finding: false,
        incomplete: false
      },
      {
        body: 'COPY --from=$REMOTE_IMAGE /bin/tool /tool',
        finding: false,
        incomplete: true
      },
      {
        body: 'COPY --from=5 /bin/tool /tool',
        finding: false,
        incomplete: true
      }
    ];
    for (const scenario of scenarios) {
      const root = await mkdtemp(
        path.join(os.tmpdir(), 'toolip-docker-copy-from-')
      );
      try {
        const lines = scenario.local
          ? [
              'FROM scratch AS builder',
              'FROM scratch',
              scenario.body,
              'USER 1000',
              'HEALTHCHECK CMD true'
            ]
          : [
              'FROM scratch',
              scenario.body,
              'USER 1000',
              'HEALTHCHECK CMD true'
            ];
        await writeFile(path.join(root, 'Dockerfile'), lines.join('\n'));
        const result = await new DockerfileAnalyzer().analyze({ root });
        expect(
          result.findings.some((item) => item.ruleId === 'TLP-DOCKER-008')
        ).toBe(scenario.finding);
        if (scenario.finding) {
          const copy = result.findings.find(
            (item) => item.ruleId === 'TLP-DOCKER-008'
          );
          expect(copy?.location?.line).toBe(scenario.line);
          expect(JSON.stringify(copy)).not.toContain('example.invalid');
        }
        expect(result.coverage.state === 'partial').toBe(scenario.incomplete);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  it('does not trust an overridable global ARG default as immutable base-image pinning', async () => {
    for (const imageLine of [
      'FROM $IMAGE',
      'FROM $' + '{IMAGE}',
      'FROM ${IMAGE:-node:20@sha256:' + 'a'.repeat(64) + '}'
    ]) {
      const root = await mkdtemp(
        path.join(os.tmpdir(), 'toolip-arg-override-')
      );
      try {
        await writeFile(
          path.join(root, 'Dockerfile'),
          [
            'ARG IMAGE=node:20@sha256:' + 'a'.repeat(64),
            imageLine,
            'USER 1000',
            'HEALTHCHECK CMD true'
          ].join('\n')
        );
        const result = await new DockerfileAnalyzer().analyze({ root });
        expect(result.coverage.state).toBe('partial');
        expect(result.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('unresolved build argument')
          ])
        );
        expect(
          result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-003')
        ).toBeUndefined();
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  it('does not accept a short or malformed base digest as an immutable image pin', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-short-digest-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        'FROM node:20@sha256:abc\nUSER 1000\nHEALTHCHECK CMD true\n'
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-003')
      ).toMatchObject({ location: { line: 1 } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('ignores late escape directives and marks their unsupported USER result incomplete', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-late-escape-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM scratch',
          '# escape=`',
          'USER 1000 \\',
          ':0',
          'HEALTHCHECK CMD true'
        ].join('\n')
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('late parser escape directive')
        ])
      );
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-001')
      ).toMatchObject({ confidence: 'low', location: { line: 3 } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not trust a backslash-escaped FROM argument as a digest-pinned image', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-escaped-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'ARG IMAGE=node:20@sha256:' + 'a'.repeat(64),
          'FROM \\$IMAGE',
          'USER 1000',
          'HEALTHCHECK CMD true'
        ].join('\n')
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('unresolved build argument')
        ])
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not classify escaped FROM variables as resolved image tags', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-escape-'));
    try {
      for (const [directive, escapedFrom] of [
        ['', 'FROM \\$IMAGE'],
        ['# escape=`\n', 'FROM `$IMAGE']
      ]) {
        await writeFile(
          path.join(root, 'Dockerfile'),
          `${directive}ARG IMAGE=node:20\n${escapedFrom}\nUSER 1000\nHEALTHCHECK CMD true\n`
        );
        const result = await new DockerfileAnalyzer().analyze({ root });
        expect(result.coverage.state).toBe('partial');
        expect(result.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('unresolved build argument')
          ])
        );
        expect(
          result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-003')
        ).toBe(false);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('applies Docker ARG set and non-empty fallback modifiers', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-arg-mod-')
    );
    try {
      for (const [modifier, expectedFinding] of [
        ['+', true],
        [':+', false]
      ] as const) {
        await writeFile(
          path.join(root, 'Dockerfile'),
          `ARG SOURCE=\nARG SELECTED=\${SOURCE${modifier}node:22}\nFROM $SELECTED\nUSER 1000\nHEALTHCHECK CMD true\n`
        );
        const result = await new DockerfileAnalyzer().analyze({ root });
        expect(
          result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-003')
        ).toBe(expectedFinding);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps unsupported ARG modifiers unresolved instead of trusting an image value', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-arg-unsupported-')
    );
    try {
      const digest = 'a'.repeat(64);
      for (const expression of [
        '$' + '{IMAGE/pattern/replacement}',
        '$' + '{IMAGE:?synthetic-build-error}'
      ]) {
        await writeFile(
          path.join(root, 'Dockerfile'),
          [
            `ARG IMAGE=node:22@sha256:${digest}`,
            `FROM ${expression}`,
            'USER 1000',
            'HEALTHCHECK CMD true'
          ].join('\n')
        );
        const result = await new DockerfileAnalyzer().analyze({ root });
        expect(result.coverage.state).toBe('partial');
        expect(result.warnings).toContain(
          'Dockerfile:2: base image uses an unresolved build argument; digest pinning could not be verified'
        );
        expect(
          result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-003')
        ).toMatchObject({ confidence: 'low', location: { line: 2 } });
        expect(JSON.stringify(result)).not.toContain('synthetic-build-error');
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('applies escape parity consistently when expanding FROM build arguments', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-escape-parity-')
    );
    try {
      for (const [directive, fromLine, expectExpanded] of [
        ['', 'FROM \\$IMAGE', false],
        ['', 'FROM \\\\$IMAGE', true],
        ['# escape=`\n', 'FROM `$IMAGE', false],
        ['# escape=`\n', 'FROM ``$IMAGE', true]
      ] as const) {
        await writeFile(
          path.join(root, 'Dockerfile'),
          `${directive}ARG IMAGE=node:22\n${fromLine}\nUSER 1000\nHEALTHCHECK CMD true\n`
        );
        const result = await new DockerfileAnalyzer().analyze({ root });
        expect(result.coverage.state).toBe('partial');
        expect(
          result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-003')
        ).toBe(expectExpanded);
        expect(result.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('unresolved build argument')
          ])
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps malformed parser directives incomplete instead of guessing escape rules', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-directive-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        '# escape=/\nFROM scratch\nUSER 1000\nHEALTHCHECK CMD true\n'
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toContain(
        'Dockerfile:1: invalid Dockerfile escape directive; default escape semantics were used'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks custom Dockerfile frontends incomplete without executing them', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-frontend-')
    );
    try {
      const instructions = 'FROM scratch\nUSER 1000\nHEALTHCHECK CMD true\n';
      await writeFile(
        path.join(root, 'Dockerfile'),
        `# syntax=docker/dockerfile:1\n${instructions}`
      );
      const officialFrontend = await new DockerfileAnalyzer().analyze({ root });
      expect(officialFrontend.coverage.state).toBe('complete');

      await writeFile(
        path.join(root, 'Dockerfile'),
        `# syntax=example.invalid/custom-frontend:latest\n${instructions}`
      );
      const customFrontend = await new DockerfileAnalyzer().analyze({ root });
      expect(customFrontend.coverage.state).toBe('partial');
      expect(customFrontend.warnings).toContain(
        'Dockerfile:1: custom or invalid Dockerfile frontend; instruction semantics are unknown'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('preserves cancellation as incomplete Dockerfile coverage', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-cancel-'));
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        'FROM scratch\nUSER 1000\nHEALTHCHECK CMD true\n'
      );
      const controller = new AbortController();
      controller.abort();
      const result = await new DockerfileAnalyzer().analyze({
        root,
        signal: controller.signal
      });
      expect(result.coverage).toMatchObject({
        state: 'failed',
        eligible: 1,
        scanned: 0,
        skipped: 1,
        failed: 0
      });
      expect(result.warnings).toEqual(['Dockerfile: skipped (cancelled)']);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks unresolved FROM platform expressions as incomplete even when user and health are explicit', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-platform-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        'FROM --platform=$' +
          '{TARGETPLATFORM} scratch\nUSER 1000\nHEALTHCHECK CMD true\n'
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(result.coverage.state).toBe('partial');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

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
      expect(secretFinding?.evidence?.[0]?.summary).toContain(
        'content redacted'
      );
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
      expect(secretFindings[0]?.evidence?.[0]?.summary).toContain(
        'content redacted'
      );
      expect(JSON.stringify(secretFindings)).not.toContain(
        'synthetic-secret-value'
      );
      expect(rootFinding?.location?.line).toBe(7);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('handles a long continued instruction within the bounded Dockerfile budget', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-long-continuation-')
    );
    try {
      const source = [
        'FROM scratch',
        'RUN ' + Array.from({ length: 2_000 }, () => 'echo x \\').join('\n'),
        '  true',
        'USER 1000',
        'HEALTHCHECK CMD true'
      ].join('\n');
      await writeFile(path.join(root, 'Dockerfile'), source);
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(result.coverage.state).toBe('complete');
      expect(result.metadata?.bytesAnalyzed).toBe(Buffer.byteLength(source));
      expect(result.findings).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('bounds cumulative ARG expansion and leaves later image metadata unknown', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-arg-budget-')
    );
    try {
      const image = `example.invalid/${'a'.repeat(1024 * 1024)}`;
      const source = [
        `ARG IMAGE=${image}`,
        ...Array.from({ length: 10 }, () => 'FROM $IMAGE'),
        'USER 1000',
        'HEALTHCHECK CMD true'
      ].join('\n');
      await writeFile(path.join(root, 'Dockerfile'), source);
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toContain(
        'Dockerfile: Dockerfile ARG expansion budget exceeded; image metadata is unknown'
      );
      expect(JSON.stringify(result)).not.toContain('example.invalid');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not expose opaque values from matched RUN instructions', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-evidence-')
    );
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
          'USER 1000',
          'HEALTHCHECK CMD node healthcheck.js'
        ].join('\n')
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(
        result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-003')
      ).toBe(false);
      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('unresolved build argument')
        ])
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks unresolved and unsupported FROM argument expansions as incomplete', async () => {
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

      await writeFile(
        path.join(root, 'Dockerfile'),
        'FROM $' + '{IMAGE+fallback}\nUSER 1000\nHEALTHCHECK CMD true\n'
      );
      const unsupportedExpansion = await new DockerfileAnalyzer().analyze({
        root
      });
      expect(unsupportedExpansion.coverage.state).toBe('partial');
      expect(unsupportedExpansion.warnings).toContain(
        'Dockerfile:1: base image uses an unresolved build argument; digest pinning could not be verified'
      );
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
      ).toBe(true);
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-001')
      ).toMatchObject({ confidence: 'low', location: { line: 2 } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('inherits USER and HEALTHCHECK metadata through a named build stage', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-inherit-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM scratch AS build',
          'USER 1000',
          'HEALTHCHECK CMD node healthcheck.js',
          'RUN npm run build',
          'FROM build AS runtime',
          'COPY --from=build /app /app',
          'CMD ["node", "server.js"]'
        ].join('\n')
      );

      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(
        result.findings.filter((finding) =>
          ['TLP-DOCKER-001', 'TLP-DOCKER-006'].includes(finding.ruleId)
        )
      ).toEqual([]);
      expect(result.coverage.state).toBe('complete');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('handles numeric stage references and final USER/HEALTHCHECK overrides', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-docker-index-'));
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM --platform=linux/amd64 scratch AS build',
          'USER 1000',
          'HEALTHCHECK CMD node healthcheck.js',
          'FROM 0 AS runtime',
          'USER 0:0',
          'HEALTHCHECK NONE'
        ].join('\n')
      );

      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-001')
      ).toMatchObject({ location: { line: 5 }, confidence: 'high' });
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-006')
      ).toMatchObject({ location: { line: 6 }, confidence: 'high' });
      expect(result.coverage.state).toBe('complete');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps unknown external image metadata incomplete and distinguishes scratch defaults', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-unknown-')
    );
    try {
      await writeFile(path.join(root, 'Dockerfile'), 'FROM example/base:1\n');
      const external = await new DockerfileAnalyzer().analyze({ root });
      expect(external.coverage.state).toBe('partial');
      expect(
        external.findings
          .filter((finding) =>
            ['TLP-DOCKER-001', 'TLP-DOCKER-006'].includes(finding.ruleId)
          )
          .map((finding) => finding.confidence)
      ).toEqual(['low', 'low']);

      await writeFile(path.join(root, 'Dockerfile'), 'FROM scratch\n');
      const scratch = await new DockerfileAnalyzer().analyze({ root });
      expect(scratch.coverage.state).toBe('complete');
      expect(
        scratch.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-001')
      ).toMatchObject({ confidence: 'high' });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not infer a non-root identity from a username alone', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-user-name-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        'FROM scratch\nUSER app\nHEALTHCHECK CMD true\n'
      );

      const result = await new DockerfileAnalyzer().analyze({ root });

      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toContain(
        'Dockerfile:2: final stage USER is a name whose numeric identity could not be verified'
      );
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-001')
      ).toMatchObject({ confidence: 'low', location: { line: 2 } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('scans every Docker ENV assignment and ignores empty ARGs and secret mounts', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-env-list-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM scratch',
          'USER 1000',
          'HEALTHCHECK CMD true',
          'ARG API_TOKEN',
          'ENV MODE=production API_KEY="synthetic-secret-value" LOG_LEVEL=info',
          'RUN --mount=type=secret,id=deploy_token cat /run/secrets/deploy_token',
          'COPY ["local.txt", "/app/local.txt"]'
        ].join('\n')
      );

      const result = await new DockerfileAnalyzer().analyze({ root });
      const secretFindings = result.findings.filter(
        (finding) => finding.ruleId === 'TLP-DOCKER-002'
      );

      expect(secretFindings).toHaveLength(1);
      expect(secretFindings[0]?.location?.line).toBe(5);
      expect(JSON.stringify(secretFindings)).not.toContain(
        'synthetic-secret-value'
      );
      expect(
        result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-004')
      ).toBe(false);
      expect(result.coverage.state).toBe('complete');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('detects remote ADD in JSON form and remote shell execution in a heredoc', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-heredoc-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM scratch',
          'USER 1000',
          'HEALTHCHECK CMD true',
          'ADD --chown=1000:1000 ["https://example.invalid/archive.tar", "/tmp/archive.tar"]',
          "RUN <<'SCRIPT'",
          'curl https://example.invalid/install.sh | sh',
          'SCRIPT'
        ].join('\n')
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-004')
      ).toMatchObject({ location: { line: 4 } });
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-007')
      ).toMatchObject({ location: { line: 5 } });
      expect(result.coverage.state).toBe('complete');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks an unterminated Dockerfile heredoc as incomplete', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-heredoc-invalid-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        "FROM scratch\nUSER node\nHEALTHCHECK CMD true\nRUN <<'SCRIPT'\necho incomplete\n"
      );
      const result = await new DockerfileAnalyzer().analyze({ root });
      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toContain(
        'Dockerfile:4: unterminated Dockerfile heredoc; instruction semantics are unknown'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('fails closed on invalid FROM references and unknown Dockerfile instructions', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-invalid-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM scratch AS build',
          'USER 1000',
          'HEALTHCHECK CMD true',
          'FROM 8 AS runtime',
          'USER 1000',
          'HEALTHCHECK CMD true',
          'FROBNICATE dangerous',
          'ADD ["broken",]'
        ].join('\n')
      );

      const result = await new DockerfileAnalyzer().analyze({ root });

      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toContain(
        'Dockerfile:4: FROM references an invalid prior stage index; inherited metadata is unknown'
      );
      expect(result.warnings).toContain(
        'Dockerfile:7: unsupported Dockerfile instruction; semantics are unknown'
      );
      expect(result.warnings).toContain(
        'Dockerfile:8: ADD JSON form is malformed or unsupported; source semantics are unknown'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('marks dynamic built-in FROM references as unresolved', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-builtin-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM $TARGETPLATFORM AS runtime',
          'USER 1000',
          'HEALTHCHECK --timeout=5s CMD true'
        ].join('\n')
      );

      const result = await new DockerfileAnalyzer().analyze({ root });

      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toContain(
        'Dockerfile:1: base image uses an unresolved build argument; digest pinning could not be verified'
      );
      expect(
        result.findings.some((finding) => finding.ruleId === 'TLP-DOCKER-003')
      ).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not trust inherited metadata when a base stage has ONBUILD triggers', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-onbuild-')
    );
    try {
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM scratch AS parent',
          'USER 1000',
          'HEALTHCHECK CMD true',
          'ONBUILD USER root',
          'FROM parent AS runtime'
        ].join('\n')
      );

      const result = await new DockerfileAnalyzer().analyze({ root });

      expect(result.coverage.state).toBe('partial');
      expect(result.warnings).toContain(
        'Dockerfile:4: ONBUILD instruction effects are not evaluated; derived stage metadata may be unknown'
      );
      expect(
        result.findings.find((finding) => finding.ruleId === 'TLP-DOCKER-001')
      ).toMatchObject({ confidence: 'low', location: { line: 5 } });
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
