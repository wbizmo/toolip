#!/usr/bin/env node
/**
 * Static policy gate for .github/workflows/*.yml.
 *
 * Enforces release isolation and least privilege:
 * - release workflows (publish.yml, github-release.yml) are workflow_dispatch only;
 * - nothing else may publish to npm, create releases/tags, or read release secrets;
 * - no pull_request_target; every third-party action pinned to a full commit SHA;
 * - every `npm ci` passes --ignore-scripts;
 * - top-level permissions are declared and read-only; write scopes are job-level
 *   and limited to the allowlist below.
 *
 * Complexity: W workflows, J jobs, S steps in total. Time O(total YAML bytes),
 * space O(largest workflow document). Every check is a single pass.
 */
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse } from 'yaml';

const DIR = process.env.WORKFLOWS_DIR ?? '.github/workflows';
const RELEASE = new Set(['publish.yml', 'github-release.yml']);
const SHA = /^[0-9a-f]{40}$/u;
const WRITE_ALLOWED = {
  'publish.yml': new Set(['id-token']),
  'github-release.yml': new Set(['contents']),
  'codeql.yml': new Set(['security-events'])
};
const problems = [];
const fail = (file, message) => problems.push(`${file}: ${message}`);

const files = (await readdir(DIR)).filter((f) => /\.ya?ml$/u.test(f)).sort();
for (const file of files) {
  const text = await readFile(path.join(DIR, file), 'utf8');
  const doc = parse(text);
  const triggers = Object.keys(doc.on ?? doc.true ?? {});
  const release = RELEASE.has(file);

  if (triggers.includes('pull_request_target'))
    fail(file, 'uses pull_request_target');
  if (
    release &&
    (triggers.length !== 1 || triggers[0] !== 'workflow_dispatch')
  ) {
    fail(
      file,
      `release workflow must be workflow_dispatch only (found ${triggers.join(', ')})`
    );
  }
  if (!release) {
    if (
      /npm\s+publish|gh\s+release\s+create|NPM_TOKEN|NODE_AUTH_TOKEN|id-token:\s*write/u.test(
        text
      )
    ) {
      fail(
        file,
        'non-release workflow references publish/release credentials or commands'
      );
    }
    if (/secrets\.(?!GITHUB_TOKEN)/u.test(text))
      fail(file, 'non-release workflow reads a secret');
    if (/git\s+(?:push|tag)\b/u.test(text))
      fail(file, 'non-release workflow pushes or tags');
  }

  const top = doc.permissions;
  if (top === undefined || typeof top !== 'object') {
    fail(file, 'top-level permissions must be declared explicitly');
  } else {
    for (const [scope, level] of Object.entries(top)) {
      if (level === 'write') fail(file, `top-level write permission: ${scope}`);
    }
  }
  const allowed = WRITE_ALLOWED[file] ?? new Set();
  for (const [jobName, job] of Object.entries(doc.jobs ?? {})) {
    for (const [scope, level] of Object.entries(job.permissions ?? {})) {
      if (level === 'write' && !allowed.has(scope)) {
        fail(
          file,
          `job ${jobName} requests unapproved write permission ${scope}`
        );
      }
    }
    if (!job['timeout-minutes'] && !release)
      fail(file, `job ${jobName} lacks timeout-minutes`);
    for (const step of job.steps ?? []) {
      if (
        typeof step.run === 'string' &&
        /\bnpm\s+ci\b(?![^\n]*--ignore-scripts)/u.test(step.run)
      ) {
        fail(
          file,
          `job ${jobName}: npm ci must use --ignore-scripts so dependency lifecycle scripts never run`
        );
      }
      if (!step.uses || step.uses.startsWith('./')) continue;
      const ref = step.uses.split('@')[1] ?? '';
      if (!SHA.test(ref))
        fail(
          file,
          `job ${jobName}: ${step.uses} is not pinned to a full commit SHA`
        );
    }
  }
}

if (problems.length > 0) {
  console.error(`Workflow policy check failed:\n- ${problems.join('\n- ')}`);
  process.exit(1);
}
console.log(`Workflow policy verified for ${files.length} workflow(s).`);
