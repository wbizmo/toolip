#!/usr/bin/env node
/**
 * Supply-chain integrity gate for package-lock.json.
 *
 * Fails when any locked package is resolved from somewhere other than the
 * public npm registry over HTTPS, lacks an integrity hash, or uses a weak hash
 * algorithm. Also rejects git/file/http specifiers and install scripts that are
 * not already on the reviewed allowlist.
 *
 * Complexity: single pass over P locked packages with R advisory ranges indexed by name. Time O(P + R), space O(P + R) for the
 * parsed lockfile; the findings list is bounded by P.
 */
import { readFile } from 'node:fs/promises';
import semver from 'semver';

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
if (lock.packages?.['']?.version !== manifest.version) {
  problems.push(
    `lockfile root package version ${lock.packages?.['']?.version} != package.json ${manifest.version}`
  );
}
if (
  lock.name !== manifest.name ||
  lock.packages?.['']?.name !== manifest.name
) {
  problems.push('lockfile package name does not match package.json');
}

// Offline advisory regression gate: no installed copy may fall in a known
// vulnerable range (issues #50, #51). Index by package name: O(P + R) total.
const advisoryFile =
  process.env.ADVISORY_FLOORS ?? 'security/advisory-floors.json';
const advisories = JSON.parse(await readFile(advisoryFile, 'utf8')).packages;

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
  const name =
    entry.name ??
    location.slice(
      location.lastIndexOf('node_modules/') + 'node_modules/'.length
    );
  const policy = Object.hasOwn(advisories, name) ? advisories[name] : undefined;
  if (
    policy &&
    typeof entry.version === 'string' &&
    semver.satisfies(entry.version, policy.vulnerable, {
      includePrerelease: true
    })
  ) {
    problems.push(
      `${location}: ${name}@${entry.version} is in vulnerable range "${policy.vulnerable}" (${policy.advisories.join(', ')})`
    );
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
