import { createHmac, randomBytes } from 'node:crypto';

const fingerprintKey = randomBytes(32);

/** Redacts common credential forms before untrusted text crosses an output boundary. */
export function redactSensitiveText(value: string): string {
  return value
    .replace(
      /([a-z][a-z0-9+.-]*:\/\/)(?=[^\s/?#]*@)[^\s/?#]*@/gi,
      '$1[redacted]@'
    )
    .replace(
      /([?&](?:token|access_token|refresh_token|api[_-]?key|password|secret|signature|sig)=)[^&#\s]+/gi,
      '$1[redacted]'
    )
    .replace(
      /(authorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi,
      '$1[redacted]'
    )
    .replace(/(authorization\s*:\s*Basic\s+)[A-Za-z0-9+/]+=*/gi, '$1[redacted]')
    .replace(
      /((?:-H|--header)\s+["']?authorization:\s*Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi,
      '$1[redacted]'
    )
    .replace(
      /((?:-H|--header)\s+["']?authorization:\s*Basic\s+)[A-Za-z0-9+/]+=*/gi,
      '$1[redacted]'
    )
    .replace(
      /\b((?:NPM|GITHUB|GITLAB|AWS|AZURE|API|ACCESS|AUTH|JWT)[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)|(?:token|api[_-]?key|password|passphrase|passwd|pwd|client_secret|secret))\s*([=:])\s*(["'])(.*?)\3/gi,
      '$1$2[redacted]'
    )
    .replace(
      /(^|\s)(--?(?:token|password|secret|api[-_]?key|auth)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s]+)/gim,
      '$1$2[redacted]'
    )
    .replace(
      /\b((?:NPM|GITHUB|GITLAB|AWS|AZURE|API|ACCESS|AUTH|JWT)[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)|(?:token|api[_-]?key|password|passphrase|passwd|pwd|client_secret|secret))\s*([=:])\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,
      '$1$2[redacted]'
    )
    .replace(
      /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b/g,
      '[redacted-token]'
    );
}

/** Redacts high-confidence credentials without rewriting identifier suffixes. */
function redactIdentifier(value: string): string {
  return value
    .replace(
      /([a-z][a-z0-9+.-]*:\/\/)(?=[^\s/?#]*@)[^\s/?#]*@/gi,
      '$1[redacted]@'
    )
    .replace(
      /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b/g,
      '[redacted-token]'
    );
}

/** Recursively sanitizes arbitrary analyzer payloads, including errors and nested metadata. */
export function sanitizeOutput<T>(
  value: T,
  depth = 0,
  sensitiveContext = false
): T {
  if (depth > 32) return '[truncated]' as T;
  if (sensitiveContext && typeof value === 'string') return '[redacted]' as T;
  if (typeof value === 'string') return redactSensitiveText(value) as T;
  if (value instanceof Error) {
    if (sensitiveContext) return '[redacted]' as T;
    return {
      name: redactSensitiveText(value.name),
      message: redactSensitiveText(value.message)
    } as T;
  }
  if (Array.isArray(value))
    return value.map((item) =>
      sanitizeOutput(item, depth + 1, sensitiveContext)
    ) as T;
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => {
        if (
          !sensitiveContext &&
          (key === 'id' || key === 'ruleId') &&
          typeof item === 'string'
        ) {
          return [key, redactIdentifier(item)];
        }
        if (/fingerprint/i.test(key)) {
          const fingerprint =
            typeof item === 'string'
              ? createHmac('sha256', fingerprintKey).update(item).digest('hex')
              : '[redacted-fingerprint]';
          return [key, fingerprint];
        }
        if (/hash/i.test(key)) return [key, '[redacted-fingerprint]'];
        const sensitiveKey =
          /password|passphrase|passwd|credential|authorization|secret|token|api[_-]?key/i.test(
            key
          );
        return [
          redactSensitiveText(key),
          sanitizeOutput(item, depth + 1, sensitiveContext || sensitiveKey)
        ];
      })
    ) as T;
  }
  return value;
}
