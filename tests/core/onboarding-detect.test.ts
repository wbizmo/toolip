import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { discoverOnboardingEcosystems } from '../../src/core/onboarding/detect-ecosystems.js';

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) =>
    rm(root, { recursive: true, force: true })
  ));
});

async function fixture(files: readonly string[]): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-onboard-'));
  roots.push(root);
  for (const name of files) {
    const full = path.join(root, name);
    await mkdir(path.dirname(full), { recursive: true });
    // A deliberate invalid lockfile: discovery must not falsely claim it
    // contains an authoritative dependency graph.
    await writeFile(full, 'inert fixture; not a valid dependency lockfile');
  }
  return root;
}

describe('first-scan polyglot onboarding', () => {
  it('lists six ecosystems without executing files or claiming verified installed packages', async () => {
    const root = await fixture([
      'package.json',
      'package-lock.json',
      'apps/python/pyproject.toml',
      'apps/python/uv.lock',
      'services/api/go.mod',
      'services/api/go.sum',
      'rust/Cargo.toml',
      'rust/Cargo.lock',
      'java/pom.xml',
      'java/maven-dependency-tree.json',
      'php/composer.json',
      'php/composer.lock'
    ]);
    const result = await discoverOnboardingEcosystems(root);
    expect(result.detected.map((item) => item.ecosystem)).toEqual([
      'javascript', 'python', 'go', 'rust', 'java', 'php'
    ]);
    expect(result.detected.every((item) =>
      item.confidence === 'lockfile-candidate'
    )).toBe(true);
    expect(result.status).toBe('requires-scan');
    expect(result.completeSecurityScanPerformed).toBe(false);
    expect(result.scriptsExecutedByDetection).toBe(false);
    expect(result.firstScanCommand).toBe('toolip scan --offline --fail-on-incomplete');
    expect(JSON.stringify(result)).not.toContain('exact installed versions verified');
  });

  it('does not promote a Python or Go manifest without a lock graph into verified resolution', async () => {
    const root = await fixture([
      'backend/pyproject.toml',
      'service/go.mod',
      'library/Cargo.toml'
    ]);
    const result = await discoverOnboardingEcosystems(root);
    expect(result.detected.map((item) => item.confidence)).toEqual([
      'manifest-only', 'manifest-only', 'manifest-only'
    ]);
    expect(result.networkOnFirstScan).toBe(false);
    expect(result.installationMayUseNetwork).toBe(true);
  });

  it('treats a repo without ecosystem markers as scannable but not complete', async () => {
    const root = await fixture(['src/handler.ts']);
    const result = await discoverOnboardingEcosystems(root);
    expect(result.detected).toEqual([]);
    expect(result.status).toBe('requires-scan');
    expect(result.completeSecurityScanPerformed).toBe(false);
  });
});
