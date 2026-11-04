#!/usr/bin/env node
/**
 * Formatting gate for files changed relative to a base revision.
 *
 * Usage: node scripts/check-changed.mjs [baseRef] [headRef]
 *   baseRef defaults to $BASE_SHA, then origin/main.
 *   headRef defaults to $HEAD_SHA, then HEAD.
 *
 * Complexity: one `git diff` (O(F) paths) plus one Prettier pass over the
 * changed files in chunks of CHUNK_SIZE. Time O(B) in changed bytes; peak space
 * O(F) path strings plus Prettier's per-file working set. Chunking keeps the
 * command line below Windows limits. No network access; uses the locked
 * Prettier from node_modules.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';

const CHUNK_SIZE = 50;
const FORMATTED = /\.(?:[cm]?[jt]sx?|json|ya?ml|md)$/u;
const HISTORICAL =
  /^(?:CHANGELOG\.md|RELEASE_NOTES_[^/]+\.md|package-lock\.json)$/u;

const base = process.argv[2] ?? process.env.BASE_SHA ?? 'origin/main';
const head = process.argv[3] ?? process.env.HEAD_SHA ?? 'HEAD';
const prettier = path.join('node_modules', 'prettier', 'bin', 'prettier.cjs');

if (!existsSync(prettier)) {
  console.error('Prettier is not installed. Run `npm ci` first.');
  process.exit(2);
}

const mergeBase = execFileSync('git', ['merge-base', base, head], {
  encoding: 'utf8'
}).trim();

const changed = execFileSync(
  'git',
  ['diff', '--name-only', '-z', '--diff-filter=ACMR', mergeBase, head],
  { encoding: 'utf8' }
)
  .split('\0')
  .filter(Boolean)
  .filter(
    (file) => FORMATTED.test(file) && !HISTORICAL.test(file) && existsSync(file)
  );

let failed = false;
for (let i = 0; i < changed.length; i += CHUNK_SIZE) {
  const result = spawnSync(
    process.execPath,
    [prettier, '--check', '--', ...changed.slice(i, i + CHUNK_SIZE)],
    { stdio: 'inherit' }
  );
  if (result.status !== 0) failed = true;
}

console.log(
  `Checked formatting of ${changed.length} changed file(s) against ${mergeBase.slice(0, 12)}.`
);
if (failed) {
  console.error('Formatting check failed. Run `npx prettier --write <file>`.');
  process.exit(1);
}
