import { createHash } from 'node:crypto';

export const SECRET_FIXTURE_MARKER = 'toolip:allow-secret-fixture';

export type SecretMatch = {
  value: string;
  index: number;
  line: number;
  column: number;
  fingerprint: string;
  fixtureAllowed: boolean;
};

export function isTestFile(relativePath?: string): boolean {
  if (!relativePath) return false;

  return (
    relativePath.startsWith('tests/') ||
    relativePath.includes('/tests/') ||
    relativePath.includes('/__tests__/') ||
    /\.(test|spec)\.[cm]?[jt]sx?$/.test(relativePath)
  );
}

export function secretFingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function secretEvidence(value: string): {
  summary: string;
  fingerprint: string;
} {
  const fingerprint = secretFingerprint(value);
  return {
    summary: `[redacted secret; sha256:${fingerprint.slice(0, 12)}]`,
    fingerprint
  };
}

export function findSecretMatches(
  content: string,
  pattern: RegExp
): SecretMatch[] {
  const regex = new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
  );
  const lines = content.split('\n');
  const matches: SecretMatch[] = [];

  for (const match of content.matchAll(regex)) {
    const value = match[0];
    const index = match.index ?? 0;
    const { line, column } = lineAndColumn(content, index);
    const currentLine = lines[line - 1] ?? '';
    const previousLine = lines[line - 2] ?? '';

    matches.push({
      value,
      index,
      line,
      column,
      fingerprint: secretFingerprint(value),
      fixtureAllowed:
        currentLine.includes(SECRET_FIXTURE_MARKER) ||
        previousLine.includes(SECRET_FIXTURE_MARKER)
    });
  }

  return matches;
}

export function lineAndColumn(
  content: string,
  index: number
): { line: number; column: number } {
  const before = content.slice(0, index);
  const lastNewline = before.lastIndexOf('\n');
  return {
    line: before.split('\n').length,
    column: index - lastNewline
  };
}
