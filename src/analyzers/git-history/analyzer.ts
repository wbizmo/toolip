import { spawn } from 'node:child_process';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import type { Finding } from '../../contracts/finding.js';
import {
  isTestFile,
  SECRET_FIXTURE_MARKER,
  secretEvidence
} from '../../core/secret-utils.js';
import { historicalSecretPatterns } from './secret-patterns.js';

type CommitMetadata = {
  commit: string;
  author: string;
  date: string;
};

type AddedLine = {
  file?: string;
  content: string;
};

async function streamGitLog(
  root: string,
  maxCommits: number,
  signal: AbortSignal | undefined,
  onAddedLine: (commit: CommitMetadata, line: AddedLine) => void
): Promise<number> {
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
        stdio: ['ignore', 'pipe', 'pipe']
      }
    );

    let pending = '';
    let stderr = '';
    let currentFile: string | undefined;
    let currentCommit: CommitMetadata | undefined;
    let commitsScanned = 0;
    let cancelled = false;

    const consume = (line: string): void => {
      if (line.startsWith('__TOOLIP_COMMIT__')) {
        const [commit, author, date] = line
          .slice('__TOOLIP_COMMIT__'.length)
          .split('\t');
        currentCommit = {
          commit: commit ?? 'unknown',
          author: author ?? 'unknown',
          date: date ?? 'unknown'
        };
        currentFile = undefined;
        commitsScanned += 1;
        return;
      }

      if (line.startsWith('+++ b/')) {
        currentFile = line.slice('+++ b/'.length);
        return;
      }

      if (line.startsWith('+++ /dev/null')) {
        currentFile = undefined;
        return;
      }

      if (
        currentCommit &&
        line.startsWith('+') &&
        !line.startsWith('+++')
      ) {
        onAddedLine(currentCommit, {
          file: currentFile,
          content: line.slice(1)
        });
      }
    };

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');

    child.stdout.on('data', (chunk: string) => {
      pending += chunk;
      const lines = pending.split('\n');
      pending = lines.pop() ?? '';
      for (const line of lines) consume(line);
    });

    child.stderr.on('data', (chunk: string) => {
      stderr = `${stderr}${chunk}`.slice(-64 * 1024);
    });

    const abort = (): void => {
      cancelled = true;
      child.kill('SIGTERM');
    };

    signal?.addEventListener('abort', abort, { once: true });
    child.on('error', reject);

    child.on('close', (code) => {
      signal?.removeEventListener('abort', abort);
      if (pending) consume(pending);

      if (cancelled) {
        reject(new Error('Git history analysis was cancelled.'));
        return;
      }

      if (code !== 0) {
        reject(new Error(stderr.trim() || `git log exited with ${code}.`));
        return;
      }

      resolve(commitsScanned);
    });
  });
}

export class GitHistorySecretAnalyzer implements Analyzer {
  readonly id = 'git-history-secrets';
  readonly version = '1.1.0';

  constructor(private readonly maxCommits = 1000) {}

  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const findings: Finding[] = [];
    const seen = new Set<string>();

    const commitsScanned = await streamGitLog(
      context.root,
      this.maxCommits,
      context.signal,
      (section, line) => {
        if (line.content.includes(SECRET_FIXTURE_MARKER)) return;

        for (const pattern of historicalSecretPatterns) {
          pattern.regex.lastIndex = 0;

          for (const match of line.content.matchAll(pattern.regex)) {
            const evidence = secretEvidence(match[0]);
            const column = (match.index ?? 0) + 1;
            const key =
              `${pattern.id}:${section.commit}:` +
              `${line.file ?? 'unknown'}:${column}:` +
              evidence.fingerprint.slice(0, 16);

            if (seen.has(key)) continue;
            seen.add(key);

            const testFixtureCandidate = isTestFile(line.file);

            findings.push({
              id: key,
              ruleId: pattern.id,
              title: testFixtureCandidate
                ? `Potential historical test fixture: ${pattern.title}`
                : pattern.title,
              category: 'git-history-secret',
              severity: pattern.severity,
              confidence: testFixtureCandidate ? 'medium' : 'high',
              message: testFixtureCandidate
                ? `A secret-like value was introduced in test file ${line.file ?? 'unknown'} in commit ${section.commit}. Severity is preserved until the value is explicitly identified as synthetic fixture data.`
                : `A secret-like value was introduced in commit ${section.commit}.`,
              source: 'git-history',
              location: line.file
                ? { file: line.file, column }
                : undefined,
              evidence: [evidence],
              remediation: {
                summary: testFixtureCandidate
                  ? 'Confirm that the value is synthetic test data. Use the explicit Toolip fixture marker only for intentionally fake credentials.'
                  : 'Revoke or rotate the credential immediately, then remove it from repository history using an approved history-rewrite process.'
              },
              metadata: {
                commit: section.commit,
                author: section.author,
                date: section.date,
                file: line.file,
                testFixtureCandidate
              }
            });
          }
        }
      }
    );

    return {
      analyzer: this.id,
      durationMs: Math.round(performance.now() - startedAt),
      findings,
      metadata: {
        commitsScanned,
        findings: findings.length,
        testFixtureCandidates: findings.filter(
          (finding) => finding.metadata?.testFixtureCandidate === true
        ).length,
        maxCommits: this.maxCommits
      }
    };
  }
}
