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
    if (item.expiresAt !== undefined && !(Date.parse(item.expiresAt) > now)) {
      continue;
    }
    const key = JSON.stringify([item.ruleId, item.filePath]);
    if (!index.has(key)) index.set(key, item);
  }
  return index;
}

/** Identifies test-source paths without treating them as trusted suppressions. */
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

/** Returns a redacted summary and sensitive internal fingerprint for a match. */
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
  const lineStarts = findLineStarts(content);
  let currentLine = 0;

  for (const match of content.matchAll(regex)) {
    const value = match[0];
    const index = match.index ?? 0;
    while (
      currentLine + 1 < lineStarts.length &&
      (lineStarts[currentLine + 1] ?? Number.POSITIVE_INFINITY) <= index
    ) {
      currentLine += 1;
    }
    const lineStart = lineStarts[currentLine] ?? 0;
    matches.push({
      value,
      index,
      line: currentLine + 1,
      column: index - lineStart + 1,
      fingerprint: secretFingerprint(value)
    });
  }

  return matches;
}

/** Converts a source string offset into one-based line and column coordinates. */
export function lineAndColumn(
  content: string,
  index: number
): { line: number; column: number } {
  return createLineLocator(content)(index);
}

/** Precomputes source line offsets once for repeated configuration matches. */
export function createLineLocator(
  content: string
): (index: number) => { line: number; column: number } {
  const lineStarts = findLineStarts(content);
  return (index) => {
    let low = 0;
    let high = lineStarts.length;
    while (low < high) {
      const middle = low + ((high - low) >> 1);
      if ((lineStarts[middle] ?? Number.POSITIVE_INFINITY) <= index)
        low = middle + 1;
      else high = middle;
    }
    const lineIndex = Math.max(0, low - 1);
    return {
      line: lineIndex + 1,
      column: index - (lineStarts[lineIndex] ?? 0) + 1
    };
  };
}

function findLineStarts(content: string): number[] {
  const starts = [0];
  for (let index = 0; index < content.length; index += 1) {
    if (content.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}
