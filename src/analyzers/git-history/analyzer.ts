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

type AddedLine = {
  file?: string;
  content: string;
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

function isTestFile(file?: string): boolean {
  if (!file) {
    return false;
  }

  return (
    file.startsWith('tests/') ||
    file.includes('/tests/') ||
    file.includes('/__tests__/') ||
    /\.(test|spec)\.[cm]?[jt]sx?$/.test(file)
  );
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
  return output
    .split('__TOOLIP_COMMIT__')
    .filter(Boolean)
    .map((section) => {
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

function addedLines(body: string): AddedLine[] {
  const output: AddedLine[] = [];
  let currentFile: string | undefined;

  for (const line of body.split('\n')) {
    if (line.startsWith('+++ b/')) {
      currentFile = line.slice('+++ b/'.length);
      continue;
    }

    if (line.startsWith('+++ /dev/null')) {
      currentFile = undefined;
      continue;
    }

    if (
      line.startsWith('+') &&
      !line.startsWith('+++')
    ) {
      output.push({
        file: currentFile,
        content: line.slice(1)
      });
    }
  }

  return output;
}

export class GitHistorySecretAnalyzer
  implements Analyzer
{
  readonly id = 'git-history-secrets';
  readonly version = '1.0.1';

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
      for (const line of addedLines(section.body)) {
        for (
          const pattern of historicalSecretPatterns
        ) {
          pattern.regex.lastIndex = 0;

          for (
            const match of line.content.matchAll(
              pattern.regex
            )
          ) {
            const value = match[0];
            const secretFingerprint =
              fingerprint(value);

            const key =
              `${pattern.id}:${section.commit}:` +
              `${line.file ?? 'unknown'}:` +
              secretFingerprint;

            if (seen.has(key)) {
              continue;
            }

            seen.add(key);

            const testFixture =
              isTestFile(line.file);

            findings.push({
              id: key,
              ruleId: pattern.id,
              title: testFixture
                ? `Potential historical test fixture: ${pattern.title}`
                : pattern.title,
              category: 'git-history-secret',
              severity: testFixture
                ? 'low'
                : pattern.severity,
              confidence: testFixture
                ? 'medium'
                : 'high',
              message: testFixture
                ? `A secret-like value was introduced in test file ${line.file ?? 'unknown'} in commit ${section.commit}. Confirm that it is synthetic fixture data.`
                : `A secret-like value was introduced in commit ${section.commit}.`,
              source: 'git-history',
              location: line.file
                ? {
                    file: line.file
                  }
                : undefined,
              evidence: [
                {
                  summary: redact(value),
                  fingerprint:
                    secretFingerprint
                }
              ],
              remediation: {
                summary: testFixture
                  ? 'Confirm that the value is synthetic test data. Replace realistic credential fixtures with clearly fake placeholders where possible.'
                  : 'Revoke or rotate the credential immediately, then remove it from repository history using an approved history-rewrite process.'
              },
              metadata: {
                commit: section.commit,
                author: section.author,
                date: section.date,
                file: line.file,
                testFixture
              }
            });
          }
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
        testFixtures: findings.filter(
          (finding) =>
            finding.metadata?.testFixture === true
        ).length,
        maxCommits:
          this.maxCommits
      }
    };
  }
}
