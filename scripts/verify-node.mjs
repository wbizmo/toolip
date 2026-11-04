#!/usr/bin/env node
/**
 * Security gate for the Node.js runtime itself (issue #92).
 *
 * Usage: node scripts/verify-node.mjs [versionOverride]
 *
 * Fails when the running (or supplied) Node.js is below the reviewed patch
 * floor in security/runtime-floors.json, is an unsupported major, or when
 * package.json#engines.node admits a version the floors reject. Dependency-free
 * on purpose: it runs before `npm ci` in a fresh checkout. O(A) for A engine
 * alternatives, O(1) space.
 */
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)$/u;

export function parse(version) {
  const match = SEMVER.exec(String(version).trim());
  if (!match) throw new Error(`Unparseable Node.js version: "${version}".`);
  return match.slice(1).map(Number);
}

export function compare(a, b) {
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

/** Version passes when its major has a floor and it is at or above it. */
export function meetsFloor(version, floors) {
  const parsed = parse(version);
  const floor = floors[String(parsed[0])];
  return floor !== undefined && compare(parsed, parse(floor)) >= 0;
}

/**
 * Evaluates the engines subset used by Toolip: `^M.m.p` and `>=M.m.p <N`
 * alternatives joined by `||`. Anything else is rejected so a loosened range
 * cannot silently bypass the gate.
 */
export function satisfiesEngines(version, range) {
  const parsed = parse(version);
  return range.split('||').some((alternative) => {
    const text = alternative.trim();
    let match = /^\^(\d+\.\d+\.\d+)$/u.exec(text);
    if (match) {
      const min = parse(match[1]);
      return parsed[0] === min[0] && compare(parsed, min) >= 0;
    }
    match = /^>=(\d+\.\d+\.\d+) <(\d+)$/u.exec(text);
    if (match) {
      return (
        compare(parsed, parse(match[1])) >= 0 && parsed[0] < Number(match[2])
      );
    }
    throw new Error(`Unsupported engines.node alternative: "${text}".`);
  });
}

export async function main(argv = process.argv) {
  const floorsFile = JSON.parse(
    await readFile(
      new URL('../security/runtime-floors.json', import.meta.url),
      'utf8'
    )
  );
  const manifest = JSON.parse(
    await readFile(new URL('../package.json', import.meta.url), 'utf8')
  );
  const version = argv[2] ?? process.versions.node;
  const problems = [];

  if (!meetsFloor(version, floorsFile.floors)) {
    problems.push(
      `Node.js ${version} is unsupported or unpatched; required floors: ${JSON.stringify(floorsFile.floors)}. ` +
        'Upgrading npm packages does not patch the Node.js binary.'
    );
  }

  // engines must reject every version just below each floor and any other major.
  for (const [major, floor] of Object.entries(floorsFile.floors)) {
    const [, minor, patch] = parse(floor);
    const below =
      patch > 0
        ? `${major}.${minor}.${patch - 1}`
        : `${major}.${minor - 1}.999`;
    if (satisfiesEngines(floor, manifest.engines.node) !== true) {
      problems.push(
        `engines.node "${manifest.engines.node}" rejects floor ${floor}.`
      );
    }
    if (satisfiesEngines(below, manifest.engines.node)) {
      problems.push(
        `engines.node "${manifest.engines.node}" admits unpatched ${below}.`
      );
    }
  }
  for (const unsupported of ['23.99.0', '25.0.0', '26.12.1']) {
    if (satisfiesEngines(unsupported, manifest.engines.node)) {
      problems.push(
        `engines.node "${manifest.engines.node}" admits unsupported ${unsupported}.`
      );
    }
  }

  if (problems.length > 0) {
    console.error(`Node.js runtime policy failed:\n- ${problems.join('\n- ')}`);
    return 1;
  }
  console.log(
    `Node.js ${version} meets floors ${JSON.stringify(floorsFile.floors)}.`
  );
  return 0;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exit(await main());
}
