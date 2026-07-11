import {
  access,
  readFile
} from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const root = process.cwd();
const manifestPath = path.join(root, 'package.json');
const cliPath = path.join(root, 'dist', 'src', 'index.js');

const manifest = JSON.parse(
  await readFile(manifestPath, 'utf8')
);

await access(cliPath);

const cliSource = await readFile(cliPath, 'utf8');

if (!cliSource.startsWith('#!/usr/bin/env node')) {
  throw new Error(
    'Built CLI is missing the Node.js executable shebang.'
  );
}

const cliVersion = execFileSync(
  process.execPath,
  [cliPath, '--version'],
  {
    cwd: root,
    encoding: 'utf8'
  }
).trim();

if (cliVersion !== manifest.version) {
  throw new Error(
    `CLI version ${cliVersion} does not match package version ${manifest.version}.`
  );
}

console.log(
  `Package verification passed for toolip@${manifest.version}.`
);
