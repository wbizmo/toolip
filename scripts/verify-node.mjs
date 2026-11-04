#!/usr/bin/env node
/**
 * Fails when the running Node.js is outside the package `engines` range, so CI
 * cannot silently run on an unpatched or unsupported runtime.
 *
 * Dependency-free on purpose: it runs before `npm ci`. Supports the caret
 * alternatives used by this package (`^M.m.p || ^M.m.p`). O(A) for A
 * alternatives, O(1) space.
 */
import { readFile } from 'node:fs/promises';

const { engines } = JSON.parse(await readFile('package.json', 'utf8'));
const current = process.versions.node.split('.').map(Number);

function satisfiesCaret(range) {
  const match = /^\^(\d+)\.(\d+)\.(\d+)$/u.exec(range.trim());
  if (!match) {
    throw new Error(`Unsupported engines.node alternative: "${range}".`);
  }
  const [major, minor, patch] = match.slice(1).map(Number);
  if (current[0] !== major) return false;
  if (current[1] !== minor) return current[1] > minor;
  return current[2] >= patch;
}

const ok = engines.node.split('||').some(satisfiesCaret);
if (!ok) {
  console.error(
    `Node.js ${process.version} does not satisfy engines.node "${engines.node}".`
  );
  process.exit(1);
}
console.log(`Node.js ${process.version} satisfies "${engines.node}".`);
