import {
  spawn
} from 'node:child_process';
import { createHash } from 'node:crypto';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import type { Finding } from '../../contracts/finding.js';
import {
  historicalSecretPatterns
} from './secret-patterns.js';

type CommitSection = {
  commit: string;
  author: string;
  date: string;
  body: string;
};

function redact(value: string): string {
  if (value.length <= 12) {
    return '[redacted]';
  }

  return (
    `${value.slice(0, 6)}` +
    '...[redacted]...' +
    `${value.slice(-4)}`
  );
}

function fingerprint(value: string): string {
  return createHash('sha256')
    .update(value)
    .digest('hex');
}

async function gitLog(
  root: string,
  maxCommits: number,
  signal?: AbortSignal
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'git',
      [
        'log',
        `--max-count=${maxCommits}`,
        '--all',
        '--no-renames',
        '--format=__TOOLIP_COMMIT__%H%x09%an%x09%aI',
        '--patch',
        '--unified=0',
        '--no-color'
      ],
      {
        cwd: root,
        stdio: [
          'ignore',
          'pipe',
          'pipe'
        ]
      }
    );

    let stdout = '';
    let stderr = '';

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');

    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });

    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });

    const abort = (): void => {
      child.kill('SIGTERM');
    };

    signal?.addEventListener(
      'abort',
      abort,
      {
        once: true
      }
    );

    child.on('error', reject);

    child.on('close', (code) => {
      signal?.removeEventListener(
        'abort',
        abort
      );

      if (code !== 0) {
        reject(
          new Error(
            stderr.trim() ||
            `git log exited with ${code}.`
          )
        );
        return;
      }

      resolve(stdout);
    });
  });
}

function sections(output: string): CommitSection[] {
  const rawSections = output
    .split('__TOOLIP_COMMIT__')
    .filter(Boolean);

  return rawSections.map((section) => {
    const newline = section.indexOf('\n');
    const header =
      newline === -1
        ? section
        : section.slice(0, newline);
    const body =
      newline === -1
        ? ''
        : section.slice(newline + 1);

    const [commit, author, date] =
      header.split('\t');

    return {
      commit: commit ?? 'unknown',
      author: author ?? 'unknown',
      date: date ?? 'unknown',
      body
    };
  });
}

function addedLines(body: string): string[] {
  return body
    .split('\n')
    .filter(
      (line) =>
        line.startsWith('+') &&
        !line.startsWith('+++')
    )
    .map((line) => line.slice(1));
}

export class GitHistorySecretAnalyzer
  implements Analyzer
{
  readonly id = 'git-history-secrets';
  readonly version = '1.0.0';

  constructor(
    private readonly maxCommits = 1000
  ) {}

  async analyze(
    context: AnalyzerContext
  ): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const output = await gitLog(
      context.root,
      this.maxCommits,
      context.signal
    );

    const findings: Finding[] = [];
    const seen = new Set<string>();
    const commitSections = sections(output);

    for (const section of commitSections) {
      const content = addedLines(
        section.body
      ).join('\n');

      for (
        const pattern of historicalSecretPatterns
      ) {
        pattern.regex.lastIndex = 0;

        for (
          const match of content.matchAll(
            pattern.regex
          )
        ) {
          const value = match[0];
          const secretFingerprint =
            fingerprint(value);

          const key =
            `${pattern.id}:${section.commit}:` +
            secretFingerprint;

          if (seen.has(key)) {
            continue;
          }

          seen.add(key);

          findings.push({
            id: key,
            ruleId: pattern.id,
            title: pattern.title,
            category: 'git-history-secret',
            severity: pattern.severity,
            confidence: 'high',
            message:
              `A secret-like value was introduced in commit ${section.commit}.`,
            source: 'git-history',
            evidence: [
              {
                summary: redact(value),
                fingerprint:
                  secretFingerprint
              }
            ],
            remediation: {
              summary:
                'Revoke or rotate the credential immediately, then remove it from repository history using an approved history-rewrite process.'
            },
            metadata: {
              commit: section.commit,
              author: section.author,
              date: section.date
            }
          });
        }
      }
    }

    return {
      analyzer: this.id,
      durationMs: Math.round(
        performance.now() - startedAt
      ),
      findings,
      metadata: {
        commitsScanned:
          commitSections.length,
        findings: findings.length,
        maxCommits:
          this.maxCommits
      }
    };
  }
}
