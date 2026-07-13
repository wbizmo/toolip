import {
  mkdtemp,
  readFile,
  rm
} from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

const tarball = process.argv[2];

if (!tarball) {
  throw new Error(
    'Usage: node scripts/verify-tarball.mjs <tarball>'
  );
}

const root = process.cwd();
const manifest = JSON.parse(
  await readFile(path.join(root, 'package.json'), 'utf8')
);

const listing = execFileSync(
  'tar',
  ['-tf', tarball],
  {
    cwd: root,
    encoding: 'utf8'
  }
)
  .split('\n')
  .filter(Boolean);

const requiredFiles = [
  'package/package.json',
  'package/README.md',
  'package/LICENSE',
  'package/dist/src/index.js'
];

for (const requiredFile of requiredFiles) {
  if (!listing.includes(requiredFile)) {
    throw new Error(
      `Release blocked: ${requiredFile} is missing from ${tarball}.`
    );
  }
}

const prefix = await mkdtemp(
  path.join(os.tmpdir(), 'toolip-packed-install-')
);

try {
  execFileSync(
    'npm',
    [
      'install',
      '--global',
      '--ignore-scripts',
      '--prefix',
      prefix,
      path.resolve(root, tarball)
    ],
    {
      cwd: root,
      stdio: 'pipe'
    }
  );

  const binary =
    process.platform === 'win32'
      ? path.join(prefix, 'toolip.cmd')
      : path.join(prefix, 'bin', 'toolip');

  const version = execFileSync(
    binary,
    ['--version'],
    {
      cwd: root,
      encoding: 'utf8'
    }
  ).trim();

  if (version !== manifest.version) {
    throw new Error(
      `Packed CLI version ${version} does not match package version ${manifest.version}.`
    );
  }

  execFileSync(
    binary,
    ['self-test'],
    {
      cwd: root,
      stdio: 'pipe'
    }
  );

  execFileSync(
    binary,
    ['--help'],
    {
      cwd: root,
      stdio: 'pipe'
    }
  );

  console.log(
    `Packed artifact verification passed for toolip@${manifest.version}.`
  );
} finally {
  await rm(prefix, {
    recursive: true,
    force: true
  });
}
