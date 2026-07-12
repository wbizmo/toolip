import { readFile } from 'node:fs/promises';
import type { Analyzer, AnalyzerContext, AnalyzerResult } from '../../contracts/analyzer.js';
import type { Finding, FindingSeverity } from '../../contracts/finding.js';
import { createScannerContext } from '../../core/scanner-context.js';

type DockerRule = {
  id: string;
  title: string;
  severity: FindingSeverity;
  test: (line: string, allLines: string[]) => boolean;
  message: string;
  remediation: string;
};

const rules: DockerRule[] = [
  {
    id: 'TLP-DOCKER-001',
    title: 'Container may run as root',
    severity: 'high',
    test: (_line, lines) => !lines.some((line) => /^USER\s+(?!root\b|0\b)/i.test(line.trim())),
    message: 'No non-root USER instruction was found.',
    remediation: 'Create and switch to a dedicated non-root user before the final command.'
  },
  {
    id: 'TLP-DOCKER-002',
    title: 'Secret-like value in Docker ARG or ENV',
    severity: 'critical',
    test: (line) => /^(ARG|ENV)\s+.*(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)/i.test(line.trim()),
    message: 'A secret-like variable is declared through ARG or ENV.',
    remediation: 'Use runtime secret injection or BuildKit secret mounts instead of image metadata.'
  },
  {
    id: 'TLP-DOCKER-003',
    title: 'Unpinned base image tag',
    severity: 'medium',
    test: (line) => /^FROM\s+\S+(?::latest)?(?:\s|$)/i.test(line.trim()) && !/@sha256:/i.test(line),
    message: 'The base image is not pinned by digest.',
    remediation: 'Pin trusted base images by immutable digest and review updates deliberately.'
  },
  {
    id: 'TLP-DOCKER-004',
    title: 'Remote ADD instruction',
    severity: 'high',
    test: (line) => /^ADD\s+https?:\/\//i.test(line.trim()),
    message: 'ADD downloads remote content during the image build.',
    remediation: 'Download explicitly, verify checksums, and use COPY for local content.'
  },
  {
    id: 'TLP-DOCKER-005',
    title: 'Package installation without cleanup',
    severity: 'low',
    test: (line) => /apt-get\s+install/i.test(line) && !/rm\s+-rf\s+\/var\/lib\/apt\/lists/i.test(line),
    message: 'apt package metadata may remain in the image layer.',
    remediation: 'Combine installation and cleanup in the same RUN instruction.'
  }
];

export class DockerfileAnalyzer implements Analyzer {
  readonly id = 'dockerfile-security';
  readonly version = '1.0.0';

  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const scanner = await createScannerContext(context.root);
    const findings: Finding[] = [];
    let dockerfiles = 0;

    for (const file of scanner.files) {
      if (!/(^|\/)Dockerfile(?:\.[^/]+)?$/i.test(file.relativePath)) continue;

      dockerfiles += 1;
      const content = await readFile(file.absolutePath, 'utf8');
      const lines = content.split(/\r?\n/);

      for (const rule of rules) {
        const matches = rule.id === 'TLP-DOCKER-001'
          ? [lines[0] ?? '']
          : lines.filter((line) => rule.test(line, lines));

        if (rule.id === 'TLP-DOCKER-001' && !rule.test('', lines)) continue;

        for (const match of matches) {
          const lineNumber = Math.max(1, lines.indexOf(match) + 1);
          findings.push({
            id: `${rule.id}:${file.relativePath}:${lineNumber}`,
            ruleId: rule.id,
            title: rule.title,
            category: 'container',
            severity: rule.severity,
            confidence: 'high',
            message: rule.message,
            source: 'dockerfile',
            location: {
              file: file.relativePath,
              line: lineNumber,
              column: 1
            },
            evidence: [{
              summary: match.trim().slice(0, 200) || 'No non-root USER instruction',
              fingerprint: `${file.relativePath}:${lineNumber}:${rule.id}`
            }],
            remediation: {
              summary: rule.remediation
            }
          });
        }
      }
    }

    return {
      analyzer: this.id,
      durationMs: Math.round(performance.now() - startedAt),
      findings,
      metadata: {
        dockerfiles,
        findings: findings.length
      }
    };
  }
}
