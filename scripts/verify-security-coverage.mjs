import { spawn } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const thresholds = new Map([
  ['src/application/analyzer-runner.ts', 0.70],
  ['src/core/github/upgrade-pr.ts', 0.45],
  ['src/core/hooks.ts', 0.60],
  ['src/core/pre-commit.ts', 0.50],
  ['src/core/secret-utils.ts', 0.60],
  ['src/core/security-doctor.ts', 0.45],
  ['src/core/vault.ts', 0.45],
  ['src/mcp/workspace-boundary.ts', 0.70]
]);

const coverageDirectory = await mkdtemp(
  path.join(os.tmpdir(), 'toolip-v8-coverage-')
);

try {
  await runTests(coverageDirectory);
  const coverageFiles = await readdir(coverageDirectory);
  const functions = new Map();

  for (const file of coverageFiles.filter((name) => name.endsWith('.json'))) {
    const raw = await readFile(path.join(coverageDirectory, file), 'utf8');
    const report = JSON.parse(raw);

    for (const script of report.result ?? []) {
      const sourcePath = matchCriticalSource(script.url);
      if (!sourcePath) continue;

      for (const fn of script.functions ?? []) {
        const range = fn.ranges?.[0];
        if (!range) continue;

        const key = [
          sourcePath,
          fn.functionName ?? '',
          range.startOffset,
          range.endOffset
        ].join(':');
        const previous = functions.get(key);
        const count = Number(range.count ?? 0);

        functions.set(key, {
          sourcePath,
          count: Math.max(previous?.count ?? 0, count)
        });
      }
    }
  }

  let failed = false;

  for (const [sourcePath, threshold] of thresholds) {
    const fileFunctions = [...functions.values()].filter(
      (entry) => entry.sourcePath === sourcePath
    );

    if (fileFunctions.length === 0) {
      console.error(`Coverage gate could not observe ${sourcePath}.`);
      failed = true;
      continue;
    }

    const covered = fileFunctions.filter((entry) => entry.count > 0).length;
    const ratio = covered / fileFunctions.length;
    const percentage = (ratio * 100).toFixed(1);
    const required = (threshold * 100).toFixed(0);

    console.log(
      `${sourcePath}: ${percentage}% function coverage (${covered}/${fileFunctions.length}, required ${required}%)`
    );

    if (ratio < threshold) {
      failed = true;
    }
  }

  if (failed) {
    throw new Error('Security-critical coverage threshold was not met.');
  }

  console.log('Security-critical coverage verification passed.');
} finally {
  await rm(coverageDirectory, { recursive: true, force: true });
}

function matchCriticalSource(url) {
  if (typeof url !== 'string' || url.length === 0) return undefined;

  const normalized = decodeURIComponent(url)
    .replaceAll('\\', '/')
    .split('?', 1)[0];

  return [...thresholds.keys()].find((sourcePath) =>
    normalized.endsWith(`/${sourcePath}`) || normalized === sourcePath
  );
}

async function runTests(directory) {
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

  await new Promise((resolve, reject) => {
    const child = spawn(npm, ['test'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        NODE_V8_COVERAGE: directory
      },
      stdio: 'inherit'
    });

    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(
        new Error(
          `Test suite failed during coverage collection (code=${code ?? 'null'}, signal=${signal ?? 'none'}).`
        )
      );
    });
  });
}
