import { createHash } from 'node:crypto';

export type SecretMatch = {
  value: string;
  index: number;
  line: number;
  column: number;
  fingerprint: string;
};

export type TrustedFixtureSuppression = {
  id: string;
  ruleId: string;
  filePath: string;
  owner: string;
  justification: string;
  expiresAt?: string;
};

/** Looks up an exact rule/path suppression in a prevalidated policy index. */
export function trustedSuppressionFor(
  suppressions: ReadonlyMap<string, TrustedFixtureSuppression>,
  ruleId: string,
  filePath: string
): TrustedFixtureSuppression | undefined {
  return suppressions.get(JSON.stringify([ruleId, filePath]));
}

/** Builds the bounded exact-key index for valid and unexpired suppressions. */
export function createFixtureSuppressionIndex(
  suppressions: readonly TrustedFixtureSuppression[] = [],
  now = Date.now()
): Map<string, TrustedFixtureSuppression> {
  const index = new Map<string, TrustedFixtureSuppression>();
  for (const item of suppressions) {
    if (!item.id.trim() || !item.owner.trim() || !item.justification.trim())
      continue;
    if (item.expiresAt && !(Date.parse(item.expiresAt) > now)) continue;
    const key = JSON.stringify([item.ruleId, item.filePath]);
    if (!index.has(key)) index.set(key, item);
  }
  return index;
}

export function isTestFile(relativePath?: string): boolean {
  if (!relativePath) return false;

  return (
    relativePath.startsWith('tests/') ||
    relativePath.includes('/tests/') ||
    relativePath.includes('/__tests__/') ||
    /\.(test|spec)\.[cm]?[jt]sx?$/.test(relativePath)
  );
}

/**
 * Stable occurrence identity for correlating/redacting findings only.
 *
 * This SHA-256 value is deliberately not treated as a password hash,
 * authentication primitive, secret commitment, or other security boundary.
 * Low-entropy values may be guessable from a fingerprint, so callers must
 * continue to treat the fingerprint as sensitive report metadata.
 */
export function secretFingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function secretEvidence(value: string): {
  summary: string;
  fingerprint: string;
} {
  const fingerprint = secretFingerprint(value);
  return {
    summary: '[redacted secret]',
    fingerprint
  };
}

/** Returns every occurrence with stable location and fingerprint metadata. */
export function findSecretMatches(
  content: string,
  pattern: RegExp
): SecretMatch[] {
  const regex = new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
  );
  const matches: SecretMatch[] = [];

  for (const match of content.matchAll(regex)) {
    const value = match[0];
    const index = match.index ?? 0;
    const { line, column } = lineAndColumn(content, index);
    matches.push({
      value,
      index,
      line,
      column,
      fingerprint: secretFingerprint(value)
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
