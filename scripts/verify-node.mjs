#!/usr/bin/env node
/**
 * Fails when the running Node.js is outside the package `engines` range, so CI
 * cannot silently run on an unpatched or unsupported runtime. O(1).
 */
import { readFile } from 'node:fs/promises';
import semver from 'semver';

const { engines } = JSON.parse(await readFile('package.json', 'utf8'));
if (!semver.satisfies(process.version, engines.node)) {
  console.error(
    `Node.js ${process.version} does not satisfy engines.node "${engines.node}".`
  );
  process.exit(1);
}
console.log(`Node.js ${process.version} satisfies "${engines.node}".`);
