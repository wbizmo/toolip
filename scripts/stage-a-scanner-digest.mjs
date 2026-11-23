import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// This module intentionally uses Node built-ins only. The protected workflow
// invokes it before npm install, so importing the scanner must not resolve any
// package from node_modules.
export async function trustedScannerDigest() {
  const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
  const repositoryRoot = path.resolve(scriptDirectory, '..');
  const files = [
    'scripts/stage-a-gate.mjs',
    'scripts/stage-a-reviewed-baseline.mjs',
    'scripts/stage-a-npm-provenance.mjs',
    'scripts/stage-a-canonical-json.mjs',
    'scripts/stage-a-scanner-digest.mjs',
    'scripts/verify-stage-a-scanner.mjs',
    'scripts/verify-node.mjs',
    'scripts/write-stage-a-artifact.mjs',
    'scripts/verify-stage-a-artifact.mjs',
    'scripts/verify-workflows.mjs',
    'vendor/stage-a-yaml-parser.mjs',
    'package.json',
    'package-lock.json',
    'tsconfig.json',
    'security/runtime-floors.json'
  ];
  const visit = async (directory) => {
    const entries = await readdir(path.join(repositoryRoot, directory), {
      withFileTypes: true
    });
    const found = [];
    for (const entry of entries.sort((left, right) =>
      left.name.localeCompare(right.name)
    )) {
      const relativePath = path.posix.join(directory, entry.name);
      if (entry.isSymbolicLink())
        throw new Error('Trusted Stage A source contains a symlink.');
      if (entry.isDirectory()) found.push(...(await visit(relativePath)));
      else if (entry.isFile() && entry.name.endsWith('.ts'))
        found.push(relativePath);
    }
    return found;
  };
  files.push(...(await visit('src')));
  files.sort();
  const digest = createHash('sha256').update('toolip-stage-a-scanner-v3\0');
  for (const relativePath of files) {
    const bytes = await readFile(path.join(repositoryRoot, relativePath));
    digest
      .update(relativePath)
      .update('\0')
      .update(String(bytes.length))
      .update('\0')
      .update(bytes);
  }
  return digest.digest('hex');
}
