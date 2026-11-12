import { createHash } from 'node:crypto';
import { parseDocument } from '../vendor/stage-a-yaml-parser.mjs';

const MAX_POLICY_BYTES = 1024 * 1024;
const MAX_CANONICAL_DEPTH = 64;
const MAX_CANONICAL_NODES = 100_000;

export function canonicalJson(value) {
  let remaining = MAX_CANONICAL_NODES;
  const visit = (current, depth) => {
    remaining--;
    if (remaining < 0 || depth > MAX_CANONICAL_DEPTH)
      throw new Error('Canonical JSON exceeds its complexity limit.');
    if (Array.isArray(current))
      return `[${current.map((item) => visit(item, depth + 1)).join(',')}]`;
    if (current && typeof current === 'object')
      return `{${Object.keys(current)
        .sort()
        .map(
          (key) => `${JSON.stringify(key)}:${visit(current[key], depth + 1)}`
        )
        .join(',')}}`;
    return JSON.stringify(current);
  };
  return visit(value, 0);
}

export function canonicalJsonSha256(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

export function npmProvenancePolicyDigest(text) {
  if (
    typeof text !== 'string' ||
    Buffer.byteLength(text, 'utf8') === 0 ||
    Buffer.byteLength(text, 'utf8') > MAX_POLICY_BYTES
  )
    throw new Error('Current Stage A npm provenance policy is unavailable.');
  const document = parseDocument(text, {
    uniqueKeys: true,
    prettyErrors: false
  });
  if (document.errors.length)
    throw new Error('Current Stage A npm provenance policy is invalid.');
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('Current Stage A npm provenance policy is invalid.');
  }
  try {
    return canonicalJsonSha256(value);
  } catch {
    throw new Error('Current Stage A npm provenance policy is invalid.');
  }
}
