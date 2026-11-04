import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

const tarball = process.argv[2];

if (!tarball) {
  throw new Error('Usage: node scripts/verify-tarball.mjs <tarball>');
}

const root = process.cwd();
const manifest = JSON.parse(
  await readFile(path.join(root, 'package.json'), 'utf8')
);

const listing = execFileSync('tar', ['-tf', tarball], {
  cwd: root,
  encoding: 'utf8'
})
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

const prefix = await mkdtemp(path.join(os.tmpdir(), 'toolip-packed-install-'));

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

  const version = execFileSync(binary, ['--version'], {
    cwd: root,
    encoding: 'utf8'
  }).trim();

  if (version !== manifest.version) {
    throw new Error(
      `Packed CLI version ${version} does not match package version ${manifest.version}.`
    );
  }

  execFileSync(binary, ['self-test'], {
    cwd: root,
    stdio: 'pipe'
  });

  execFileSync(binary, ['--help'], {
    cwd: root,
    stdio: 'pipe'
  });

  // MCP stdio smoke test against the installed tarball (issue #50). The
  // .cmd shim on Windows needs a shell, so it is covered by the source-tree
  // stdio test there instead.
  if (process.platform !== 'win32') {
    const { Client } =
      await import('@modelcontextprotocol/sdk/client/index.js');
    const { StdioClientTransport } =
      await import('@modelcontextprotocol/sdk/client/stdio.js');
    const client = new Client({ name: 'toolip-pack-smoke', version: '0.0.0' });
    try {
      await client.connect(
        new StdioClientTransport({
          command: binary,
          args: ['mcp', '--allow-root', prefix],
          stderr: 'pipe'
        })
      );
      const { tools } = await client.listTools();
      const names = tools.map((tool) => tool.name).sort();
      if (names.join(',') !== 'toolip_diff,toolip_doctor,toolip_sbom') {
        throw new Error(`Unexpected packed MCP tools: ${names.join(', ')}`);
      }
    } finally {
      await client.close();
    }
  }

  console.log(
    `Packed artifact verification passed for toolip@${manifest.version}.`
  );
} finally {
  await rm(prefix, {
    recursive: true,
    force: true
  });
}
