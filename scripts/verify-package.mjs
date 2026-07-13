import {
  access,
  chmod,
  readFile,
  stat
} from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const root = process.cwd();
const manifestPath = path.join(root, 'package.json');
const cliPath = path.join(root, 'dist', 'src', 'index.js');

const manifest = JSON.parse(
  await readFile(manifestPath, 'utf8')
);

if (manifest.name !== 'toolip') {
  throw new Error(
    `Expected package name "toolip", received "${manifest.name}".`
  );
}

await access(cliPath);

const cliSource = await readFile(cliPath, 'utf8');

if (!cliSource.startsWith('#!/usr/bin/env node')) {
  throw new Error(
    'Built CLI is missing the required Node.js shebang.'
  );
}

if (process.platform !== 'win32') {
  const fileStat = await stat(cliPath);

  if ((fileStat.mode & 0o111) === 0) {
    await chmod(cliPath, 0o755);
  }
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

execFileSync(
  process.execPath,
  [cliPath, 'self-test'],
  {
    cwd: root,
    encoding: 'utf8',
    stdio: 'pipe'
  }
);

execFileSync(
  process.execPath,
  [cliPath, '--help'],
  {
    cwd: root,
    encoding: 'utf8',
    stdio: 'pipe'
  }
);

console.log(
  `Built package verification passed for toolip@${manifest.version}.`
);
