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
// Complete, well-formed digests only: SHA-512 is 64 bytes (88 base64 chars with
// padding) and SHA-384 is 48 bytes (64 base64 chars, no padding). A prefix check
// alone would accept `sha512-not-a-digest`.
const STRONG_TOKEN =
  /^(?:sha512-[A-Za-z0-9+/]{86}==|sha384-[A-Za-z0-9+/]{64})$/u;
const isStrongIntegrity = (value) =>
  typeof value === 'string' &&
  value.trim().length > 0 &&
  value
    .trim()
    .split(/\s+/u)
    .every((token) => STRONG_TOKEN.test(token));

/**
 * Every name an entry could install as: the lockfile location, the `name` field
 * (npm aliases store the real package name there) and the name embedded in the
 * registry tarball URL. Policy is checked against all of them, so no single
 * attacker-controlled field can hide a vulnerable package. O(1) per entry.
 */
function candidateNames(location, entry) {
  const names = new Set();
  const marker = 'node_modules/';
  names.add(location.slice(location.lastIndexOf(marker) + marker.length));
  if (typeof entry.name === 'string') names.add(entry.name);
  if (
    typeof entry.resolved === 'string' &&
    entry.resolved.startsWith(REGISTRY)
  ) {
    const rest = entry.resolved.slice(REGISTRY.length);
    const end = rest.indexOf('/-/');
    if (end > 0) {
      try {
        names.add(decodeURIComponent(rest.slice(0, end)));
      } catch {
        // Malformed escapes are reported by the resolved-URL checks.
      }
    }
  }
  return names;
}
// Packages whose install scripts have been reviewed. Extend only via review.
const INSTALL_SCRIPT_ALLOWLIST = new Set([
  'node_modules/esbuild',
  'node_modules/fsevents'
]);

const lock = JSON.parse(await readFile('package-lock.json', 'utf8'));
const manifest = JSON.parse(await readFile('package.json', 'utf8'));
const problems = [];

const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
if (!isPlainObject(lock.packages)) {
  problems.push('lockfile "packages" must be an object');
}
const lockPackages = isPlainObject(lock.packages) ? lock.packages : {};

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
const rawAdvisories = JSON.parse(await readFile(advisoryFile, 'utf8')).packages;
// An array (or null/string) would make name lookups silently miss every policy.
if (!isPlainObject(rawAdvisories)) {
  problems.push('advisory policy "packages" must be a non-array object');
}
const advisories = isPlainObject(rawAdvisories) ? rawAdvisories : {};

// A mistyped range makes semver.satisfies() return false, which would let a
// vulnerable package pass silently. Validate every entry up front, including
// ones for packages that are not installed today, so a typo cannot lie in wait.
const invalidPolicies = new Set();
for (const [pkg, policy] of Object.entries(advisories)) {
  if (
    typeof policy?.vulnerable !== 'string' ||
    semver.validRange(policy.vulnerable) === null
  ) {
    problems.push(
      `advisory policy for ${pkg} has an invalid vulnerable range: ${JSON.stringify(policy?.vulnerable)}`
    );
    invalidPolicies.add(pkg);
  } else if (
    !Array.isArray(policy.advisories) ||
    policy.advisories.length === 0 ||
    !policy.advisories.every((id) => typeof id === 'string' && id.length > 0)
  ) {
    problems.push(`advisory policy for ${pkg} must list advisory identifiers`);
    invalidPolicies.add(pkg);
  }
}

for (const [location, entry] of Object.entries(lockPackages)) {
  if (location === '' || entry.link) continue;
  if (
    typeof entry.resolved !== 'string' ||
    !entry.resolved.startsWith(REGISTRY)
  ) {
    problems.push(
      `${location}: resolved outside ${REGISTRY} (${entry.resolved})`
    );
  }
  if (!isStrongIntegrity(entry.integrity)) {
    problems.push(`${location}: missing or weak integrity hash`);
  }
  for (const name of candidateNames(location, entry)) {
    const policy =
      Object.hasOwn(advisories, name) && !invalidPolicies.has(name)
        ? advisories[name]
        : undefined;
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
  `Lockfile integrity verified for ${Object.keys(lockPackages).length - 1} packages.`
);
