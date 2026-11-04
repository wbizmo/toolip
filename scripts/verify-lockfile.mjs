#!/usr/bin/env node
/**
 * Supply-chain integrity gate for package-lock.json.
 *
 * Fails when any locked package is resolved from somewhere other than the
 * public npm registry over HTTPS, lacks an integrity hash, or uses a weak hash
 * algorithm. Also rejects git/file/http specifiers and install scripts that are
 * not already on the reviewed allowlist.
 *
 * Complexity: single pass over P locked packages. Time O(P), space O(P) for the
 * parsed lockfile; the findings list is bounded by P.
 */
import { readFile } from 'node:fs/promises';

const REGISTRY = 'https://registry.npmjs.org/';
const STRONG = /^sha(?:512|384)-/u;
// Packages whose install scripts have been reviewed. Extend only via review.
const INSTALL_SCRIPT_ALLOWLIST = new Set([
  'node_modules/esbuild',
  'node_modules/fsevents'
]);

const lock = JSON.parse(await readFile('package-lock.json', 'utf8'));
const manifest = JSON.parse(await readFile('package.json', 'utf8'));
const problems = [];

if (lock.lockfileVersion < 3) {
  problems.push(`lockfileVersion ${lock.lockfileVersion} is below 3`);
}
if (lock.version !== manifest.version) {
  problems.push(
    `lockfile version ${lock.version} != package.json ${manifest.version}`
  );
}

for (const [location, entry] of Object.entries(lock.packages ?? {})) {
  if (location === '' || entry.link) continue;
  if (
    typeof entry.resolved !== 'string' ||
    !entry.resolved.startsWith(REGISTRY)
  ) {
    problems.push(
      `${location}: resolved outside ${REGISTRY} (${entry.resolved})`
    );
  }
  if (typeof entry.integrity !== 'string' || !STRONG.test(entry.integrity)) {
    problems.push(`${location}: missing or weak integrity hash`);
  }
  if (entry.hasInstallScript && !INSTALL_SCRIPT_ALLOWLIST.has(location)) {
    problems.push(`${location}: unreviewed install script`);
  }
}

if (problems.length > 0) {
  console.error(`Lockfile integrity check failed:\n- ${problems.join('\n- ')}`);
  process.exit(1);
}
console.log(
  `Lockfile integrity verified for ${Object.keys(lock.packages).length - 1} packages.`
);
