import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createProjectSnapshot,
  dependencyFileSourceFromSnapshot,
  scannerContextFromSnapshot,
  verifyProjectSnapshot
} from '../../src/application/project-snapshot.js';
import { readNpmDependencyGraph } from '../../src/core/dependencies/inventory.js';
import { AnalysisResultCache } from '../../src/application/task-scheduler.js';
import { runSecurityDoctor } from '../../src/core/security-doctor.js';
import { createScannerContext } from '../../src/core/scanner-context.js';

const roots: string[] = [];
async function project(): Promise<string> {
  const root = await mkdtemp(
    path.join(os.tmpdir(), 'toolip-project-snapshot-')
  );
  roots.push(root);
  await mkdir(path.join(root, 'src'));
  await writeFile(path.join(root, 'src', 'a.ts'), 'export const value = 1;\n');
  return root;
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

describe('immutable project snapshots', () => {
  it('captures stable content hashes and verifies current input', async () => {
    const root = await project();
    const snapshot = await createProjectSnapshot(root, {
      gitRevision: 'a'.repeat(40),
      lockGraphDigest: 'lock',
      configDigest: 'config'
    });
    expect(snapshot.files[0]?.sha256).toHaveLength(64);
    expect(snapshot.files[0]?.fileId).toMatch(/^\d+:\d+$/u);
    expect(snapshot.files[0]?.mtimeNs).not.toBe('unknown');
    expect(snapshot.lockGraphDigest).toBe('lock');
    expect(await verifyProjectSnapshot(snapshot)).toBe(true);
    await writeFile(path.join(root, 'src', 'a.ts'), 'changed');
    expect(await verifyProjectSnapshot(snapshot)).toBe(false);
  });

  it('fails closed when the snapshot exceeds explicit file budgets', async () => {
    const root = await project();
    await expect(
      createProjectSnapshot(root, { maxTotalBytes: 2 })
    ).rejects.toThrow('snapshot incomplete');
  });

  it('freezes the complete shared scanner context derived from a snapshot', async () => {
    const root = await project();
    const snapshot = await createProjectSnapshot(root);
    const context = await scannerContextFromSnapshot(snapshot);
    const file = context.files[0];

    expect(Object.isFrozen(context)).toBe(true);
    expect(Object.isFrozen(context.files)).toBe(true);
    expect(file && Object.isFrozen(file)).toBe(true);
    expect(file?.snapshot && Object.isFrozen(file.snapshot)).toBe(true);
    expect(Object.isFrozen(context.profile)).toBe(true);
    expect(Object.isFrozen(context.profile.detected)).toBe(true);
    expect(Object.isFrozen(context.profile.languages)).toBe(true);
    expect(Object.isFrozen(context.profile.packageScripts)).toBe(true);
    expect(Object.isFrozen(context.summary.extensions)).toBe(true);
    if (file)
      expect(Reflect.set(file, 'relativePath', 'changed.ts')).toBe(false);
    expect(Reflect.set(context.profile.languages, 'js', 1)).toBe(false);

    const discoveredContext = await createScannerContext(root);
    expect(Object.isFrozen(discoveredContext)).toBe(true);
    expect(Object.isFrozen(discoveredContext.files)).toBe(true);
    expect(Object.isFrozen(discoveredContext.files[0])).toBe(true);
  });

  it('records binary identity and rejects added or replaced project inputs', async () => {
    const root = await project();
    const binaryPath = path.join(root, 'image.bin');
    await writeFile(binaryPath, Buffer.from([0, 1, 2, 3]));
    const snapshot = await createProjectSnapshot(root);
    const binary = snapshot.files.find((file) => file.path === 'image.bin');
    expect(binary?.binary).toBe(true);
    expect(binary?.content).toBeUndefined();
    expect(await verifyProjectSnapshot(snapshot)).toBe(true);

    await writeFile(path.join(root, 'new.ts'), 'export const added = true;');
    expect(await verifyProjectSnapshot(snapshot)).toBe(false);
    await rm(path.join(root, 'new.ts'));
    await writeFile(binaryPath, Buffer.from([0, 4, 2, 3]));
    expect(await verifyProjectSnapshot(snapshot)).toBe(false);
  });

  it('reuses unchanged file content and findings across incremental snapshots', async () => {
    const root = await project();
    await writeFile(path.join(root, 'src', 'b.ts'), 'eval(untrusted);\n');
    const cache = new AnalysisResultCache();
    const first = await createProjectSnapshot(root);
    const cold = await runSecurityDoctor(root, {
      snapshot: first,
      analysisCache: cache
    });
    expect(cold.cacheMetrics).toEqual({ hits: 0, misses: 2 });

    const warmSnapshot = await createProjectSnapshot(root, { previous: first });
    expect(warmSnapshot.metrics).toMatchObject({
      filesReused: 2,
      filesRead: 0
    });
    const warm = await runSecurityDoctor(root, {
      snapshot: warmSnapshot,
      analysisCache: cache
    });
    expect(warm.cacheMetrics).toEqual({ hits: 2, misses: 0 });
    expect(JSON.stringify(warm.findings)).toBe(JSON.stringify(cold.findings));

    await writeFile(
      path.join(root, 'src', 'a.ts'),
      'export const value = 2;\n'
    );
    const changedSnapshot = await createProjectSnapshot(root, {
      previous: warmSnapshot
    });
    expect(changedSnapshot.metrics).toMatchObject({
      filesReused: 1,
      filesRead: 1
    });
    const changed = await runSecurityDoctor(root, {
      snapshot: changedSnapshot,
      analysisCache: cache
    });
    // With no import edge, only the edited source file needs a fresh result.
    expect(changed.cacheMetrics).toEqual({ hits: 1, misses: 1 });
    expect(changed.findings).toHaveLength(warm.findings.length);
  });

  it('invalidates source conclusions when the captured rule configuration changes', async () => {
    const root = await project();
    await mkdir(path.join(root, '.toolip'));
    const configPath = path.join(root, '.toolip', 'config.json');
    await writeFile(configPath, '{"ruleSet":"baseline"}\n');
    const cache = new AnalysisResultCache();
    const firstSnapshot = await createProjectSnapshot(root);
    await runSecurityDoctor(root, {
      snapshot: firstSnapshot,
      analysisCache: cache
    });

    await writeFile(configPath, '{"ruleSet":"strict"}\n');
    const changedSnapshot = await createProjectSnapshot(root, {
      previous: firstSnapshot
    });
    const changed = await runSecurityDoctor(root, {
      snapshot: changedSnapshot,
      analysisCache: cache
    });

    expect(changed.cacheMetrics).toEqual({ hits: 0, misses: 2 });
  });

  it('resolves dependency lockfiles from captured snapshot bytes after the worktree changes', async () => {
    const root = await project();
    const lockPath = path.join(root, 'package-lock.json');
    const lock = (version: string) =>
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'fixture',
            version: '1.0.0',
            dependencies: { example: version }
          },
          'node_modules/example': { version }
        }
      });
    await writeFile(lockPath, lock('1.0.0'));
    const snapshot = await createProjectSnapshot(root);
    await writeFile(lockPath, lock('2.0.0'));

    const captured = await readNpmDependencyGraph(
      root,
      dependencyFileSourceFromSnapshot(snapshot)
    );
    const current = await readNpmDependencyGraph(root);
    expect(
      captured.packages.find((item) => item.name === 'example')?.version
    ).toBe('1.0.0');
    expect(
      current.packages.find((item) => item.name === 'example')?.version
    ).toBe('2.0.0');
  });
});
