import { createHmac, randomBytes } from 'node:crypto';
import { setImmediate as yieldEventLoop } from 'node:timers/promises';

const fingerprintKey = randomBytes(32);

function sanitizeFingerprintValue(value: unknown, depth = 0): unknown {
  if (depth > 32) return '[truncated]';
  if (typeof value === 'string') {
    // SARIF fingerprints are already one-way digests and must remain stable
    // across process runs for code-scanning correlation.
    if (/^[a-f0-9]{64}$/u.test(value)) return value;
    return createHmac('sha256', fingerprintKey).update(value).digest('hex');
  }
  if (Array.isArray(value))
    return value.map((item) => sanitizeFingerprintValue(item, depth + 1));
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        redactSensitiveText(key),
        sanitizeFingerprintValue(item, depth + 1)
      ])
    );
  return value;
}

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
export function redactSensitiveIdentifier(value: string): string {
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
          return [key, redactSensitiveIdentifier(item)];
        }
        if (key === 'fingerprints' || key === 'partialFingerprints')
          return [redactSensitiveText(key), sanitizeFingerprintValue(item)];
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

const maximumSerializedNodes = 1_000_000;
const maximumSerializedFragments = 100_000;
const stringChunkSize = 4_096;

/** JSON output that can be stopped at a byte, node, or cancellation budget. */
export async function serializeSanitizedOutputBounded(
  value: unknown,
  maxBytes: number,
  signal?: AbortSignal
): Promise<string> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1)
    throw new RangeError('Serialized output byte budget is invalid.');
  const fragments: string[] = [];
  const ancestors = new WeakSet<object>();
  let bytes = 0;
  let nodes = 0;

  const append = (text: string): void => {
    const nextBytes = bytes + Buffer.byteLength(text, 'utf8');
    if (nextBytes > maxBytes || fragments.length >= maximumSerializedFragments)
      throw new RangeError('Serialized output exceeds its configured budget.');
    bytes = nextBytes;
    fragments.push(text);
  };
  const checkpoint = async (): Promise<void> => {
    if (signal?.aborted) {
      const error = new Error('Serialized output was cancelled.');
      error.name = 'AbortError';
      throw error;
    }
    if (++nodes > maximumSerializedNodes)
      throw new RangeError('Serialized output exceeds its node budget.');
    if (nodes % 256 === 0) {
      await yieldEventLoop();
      if (signal?.aborted) {
        const error = new Error('Serialized output was cancelled.');
        error.name = 'AbortError';
        throw error;
      }
    }
  };

  const writeString = async (input: string): Promise<void> => {
    // Bound redaction work before applying its regular expressions.
    if (input.length > maxBytes)
      throw new RangeError('Serialized output exceeds its configured budget.');
    append('"');
    let chunk = '';
    const flush = (): void => {
      if (!chunk) return;
      append(chunk);
      chunk = '';
    };
    for (let index = 0; index < input.length; index++) {
      if (index > 0 && index % stringChunkSize === 0) {
        flush();
        await yieldEventLoop();
        if (signal?.aborted) {
          const error = new Error('Serialized output was cancelled.');
          error.name = 'AbortError';
          throw error;
        }
      }
      const code = input.charCodeAt(index);
      const character = input[index] ?? '';
      if (character === '"') chunk += '\\"';
      else if (character === '\\') chunk += '\\\\';
      else if (character === '\b') chunk += '\\b';
      else if (character === '\f') chunk += '\\f';
      else if (character === '\n') chunk += '\\n';
      else if (character === '\r') chunk += '\\r';
      else if (character === '\t') chunk += '\\t';
      else if (code < 0x20) chunk += `\\u${code.toString(16).padStart(4, '0')}`;
      else if (code >= 0xd800 && code <= 0xdbff) {
        const next = input.charCodeAt(index + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          chunk += character + (input[index + 1] ?? '');
          index++;
        } else chunk += `\\u${code.toString(16)}`;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        chunk += `\\u${code.toString(16)}`;
      } else chunk += character;
      if (chunk.length >= stringChunkSize) flush();
    }
    flush();
    append('"');
  };

  const supportedObjectValue = (item: unknown): boolean =>
    typeof item !== 'undefined' &&
    typeof item !== 'function' &&
    typeof item !== 'symbol';

  const writeFingerprint = async (
    item: unknown,
    depth: number
  ): Promise<void> => {
    await checkpoint();
    if (depth > 32) return writeString('[truncated]');
    if (typeof item === 'string') {
      if (item.length > maxBytes)
        throw new RangeError(
          'Serialized output exceeds its configured budget.'
        );
      const safe = /^[a-f0-9]{64}$/u.test(item)
        ? item
        : createHmac('sha256', fingerprintKey).update(item).digest('hex');
      return writeString(safe);
    }
    if (Array.isArray(item)) {
      if (ancestors.has(item)) return writeString('[truncated]');
      ancestors.add(item);
      try {
        append('[');
        for (let index = 0; index < item.length; index++) {
          if (index > 0) append(',');
          const descriptor = Object.getOwnPropertyDescriptor(
            item,
            String(index)
          );
          if (!descriptor || !('value' in descriptor)) append('null');
          else if (!supportedObjectValue(descriptor.value)) append('null');
          else await writeFingerprint(descriptor.value, depth + 1);
        }
        append(']');
      } finally {
        ancestors.delete(item);
      }
      return;
    }
    if (item && typeof item === 'object') {
      if (ancestors.has(item)) return writeString('[truncated]');
      ancestors.add(item);
      try {
        append('{');
        let first = true;
        for (const key in item) {
          if (!Object.hasOwn(item, key)) continue;
          await checkpoint();
          const descriptor = Object.getOwnPropertyDescriptor(item, key);
          if (!descriptor?.enumerable || !('value' in descriptor))
            throw new TypeError('MCP output contains an accessor property.');
          if (!supportedObjectValue(descriptor.value)) continue;
          if (!first) append(',');
          first = false;
          await writeString(redactSensitiveText(key));
          append(':');
          await writeFingerprint(descriptor.value, depth + 1);
        }
        append('}');
      } finally {
        ancestors.delete(item);
      }
      return;
    }
    if (item === null) append('null');
    else if (typeof item === 'number') append(JSON.stringify(item));
    else if (typeof item === 'boolean') append(item ? 'true' : 'false');
    else append('null');
  };

  const write = async (
    item: unknown,
    depth: number,
    sensitiveContext: boolean,
    arrayElement = false
  ): Promise<void> => {
    await checkpoint();
    if (depth > 32) return writeString('[truncated]');
    if (sensitiveContext && typeof item === 'string')
      return writeString('[redacted]');
    if (typeof item === 'string') {
      if (item.length > maxBytes)
        throw new RangeError(
          'Serialized output exceeds its configured budget.'
        );
      return writeString(redactSensitiveText(item));
    }
    if (item === null) {
      append('null');
      return;
    }
    if (typeof item === 'number') {
      append(JSON.stringify(item));
      return;
    }
    if (typeof item === 'boolean') {
      append(item ? 'true' : 'false');
      return;
    }
    if (
      typeof item === 'undefined' ||
      typeof item === 'function' ||
      typeof item === 'symbol'
    ) {
      append(arrayElement ? 'null' : 'null');
      return;
    }
    if (typeof item !== 'object') {
      append('null');
      return;
    }
    if (ancestors.has(item)) return writeString('[truncated]');
    ancestors.add(item);
    try {
      if (item instanceof Error) {
        if (sensitiveContext) return writeString('[redacted]');
        const nameDescriptor = Object.getOwnPropertyDescriptor(item, 'name');
        const messageDescriptor = Object.getOwnPropertyDescriptor(
          item,
          'message'
        );
        if (
          (nameDescriptor && !('value' in nameDescriptor)) ||
          (messageDescriptor && !('value' in messageDescriptor))
        )
          throw new TypeError('MCP output contains an accessor property.');
        const name =
          nameDescriptor && typeof nameDescriptor.value === 'string'
            ? nameDescriptor.value
            : 'Error';
        const message =
          messageDescriptor && typeof messageDescriptor.value === 'string'
            ? messageDescriptor.value
            : '';
        append('{');
        await writeString('name');
        append(':');
        await write(name, depth + 1, false);
        append(',');
        await writeString('message');
        append(':');
        await write(message, depth + 1, false);
        append('}');
        return;
      }
      if (Array.isArray(item)) {
        append('[');
        for (let index = 0; index < item.length; index++) {
          if (index > 0) append(',');
          const descriptor = Object.getOwnPropertyDescriptor(
            item,
            String(index)
          );
          if (!descriptor || !('value' in descriptor)) append('null');
          else await write(descriptor.value, depth + 1, sensitiveContext, true);
        }
        append(']');
        return;
      }
      append('{');
      let first = true;
      for (const key in item) {
        if (!Object.hasOwn(item, key)) continue;
        await checkpoint();
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!descriptor?.enumerable || !('value' in descriptor))
          throw new TypeError('MCP output contains an accessor property.');
        const propertyValue = descriptor.value;
        if (!supportedObjectValue(propertyValue)) continue;
        if (!first) append(',');
        first = false;
        if (key.length > maxBytes)
          throw new RangeError(
            'Serialized output exceeds its configured budget.'
          );
        await writeString(redactSensitiveText(key));
        append(':');
        if (key === 'fingerprints' || key === 'partialFingerprints') {
          await writeFingerprint(propertyValue, depth + 1);
          continue;
        }
        if (/fingerprint/i.test(key)) {
          await writeString('[redacted-fingerprint]');
          continue;
        }
        if (/hash/i.test(key)) {
          await writeString('[redacted-fingerprint]');
          continue;
        }
        const sensitiveKey =
          /password|passphrase|passwd|credential|authorization|secret|token|api[_-]?key/i.test(
            key
          );
        const identifier =
          !sensitiveContext &&
          (key === 'id' || key === 'ruleId') &&
          typeof propertyValue === 'string';
        if (identifier && (propertyValue as string).length > maxBytes)
          throw new RangeError(
            'Serialized output exceeds its configured budget.'
          );
        await write(
          identifier
            ? redactSensitiveIdentifier(propertyValue as string)
            : propertyValue,
          depth + 1,
          sensitiveContext || sensitiveKey
        );
      }
      append('}');
    } finally {
      ancestors.delete(item);
    }
  };

  await write(value, 0, false);
  return fragments.join('');
}
