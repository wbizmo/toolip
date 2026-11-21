import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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
  'package/dist/src/index.js',
  'package/dist/src/commands/npm-attestation.js',
  'package/dist/src/core/npm-package-attestation.js',
  // Worker entry for isolated analyzers (deadline-enforced AST analysis).
  'package/dist/src/application/analyzer-worker.js'
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
  execFileSync(binary, ['npm-attestation', '--help'], {
    cwd: root,
    stdio: 'pipe'
  });
  execFileSync(binary, ['npm-attestation', 'verify', '--help'], {
    cwd: root,
    stdio: 'pipe'
  });

  // The AST analyzer runs in a worker thread; prove the packed artifact can
  // start it and reports a complete analysis (issue #34, #35).
  const fixture = path.join(prefix, 'ast-fixture');
  await mkdir(fixture, { recursive: true });
  await writeFile(
    path.join(fixture, 'package.json'),
    JSON.stringify({ name: 'fixture', version: '1.0.0' })
  );
  await writeFile(path.join(fixture, 'ok.ts'), 'export const value = 1;\n');
  const astOutput = JSON.parse(
    execFileSync(binary, ['ast-scan', '--path', fixture, '--json'], {
      cwd: root,
      encoding: 'utf8'
    })
  );
  if (
    astOutput.analysis?.state !== 'complete' ||
    astOutput.analysis?.scanned !== 1
  ) {
    throw new Error(
      `Packed ast-scan did not complete in its worker: ${JSON.stringify(astOutput.analysis)}`
    );
  }

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
      if (
        names.join(',') !==
        'toolip_diff,toolip_doctor,toolip_policy_check,toolip_sbom'
      ) {
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
