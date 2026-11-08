import { createHash } from 'node:crypto';
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
    expect(cold.cacheMetrics).toEqual({
      hits: 0,
      misses: 2,
      astProjectHits: 0,
      astProjectMisses: 1
    });

    const warmSnapshot = await createProjectSnapshot(root, { previous: first });
    expect(warmSnapshot.metrics).toMatchObject({
      filesReused: 2,
      filesRead: 0
    });
    const warm = await runSecurityDoctor(root, {
      snapshot: warmSnapshot,
      analysisCache: cache
    });
    expect(warm.cacheMetrics).toEqual({
      hits: 2,
      misses: 0,
      astProjectHits: 1,
      astProjectMisses: 0
    });
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
    expect(changed.cacheMetrics).toEqual({
      hits: 1,
      misses: 1,
      astProjectHits: 0,
      astProjectMisses: 1
    });
    expect(changed.findings).toHaveLength(warm.findings.length);
  });

  it('reruns the AST worker when bounded project-cache chunks cannot be stored', async () => {
    const root = await project();
    await writeFile(path.join(root, 'src', 'b.ts'), 'eval(untrusted);\n');
    const cache = new AnalysisResultCache(100, 64, 64);
    const snapshot = await createProjectSnapshot(root);

    const first = await runSecurityDoctor(root, {
      snapshot,
      analysisCache: cache
    });
    const second = await runSecurityDoctor(root, {
      snapshot,
      analysisCache: cache
    });

    expect(first.cacheMetrics.astProjectMisses).toBe(1);
    expect(second.cacheMetrics.astProjectMisses).toBe(1);
    expect(second.cacheMetrics.astProjectHits).toBe(0);
    expect(JSON.stringify(second.findings)).toBe(
      JSON.stringify(first.findings)
    );
  });

  it('reruns AST analysis after its cached project chunk is evicted', async () => {
    const root = await project();
    await writeFile(
      path.join(root, 'src', 'b.ts'),
      'export const other = 2;\n'
    );
    const cache = new AnalysisResultCache(1);
    const snapshot = await createProjectSnapshot(root);
    const cold = await runSecurityDoctor(root, {
      snapshot,
      analysisCache: cache
    });
    cache.set('eviction', 'trigger', 'test-v1', { value: true });

    const recovered = await runSecurityDoctor(root, {
      snapshot,
      analysisCache: cache
    });

    expect(recovered.cacheMetrics.astProjectMisses).toBe(1);
    expect(recovered.cacheMetrics.astProjectHits).toBe(0);
    expect(JSON.stringify(recovered.findings)).toBe(
      JSON.stringify(cold.findings)
    );
  });

  it('rejects truncated, duplicated, and malformed AST dependency digest chunks', async () => {
    const root = await project();
    await writeFile(
      path.join(root, 'src', 'b.ts'),
      'export const other = 2;\n'
    );
    const snapshot = await createProjectSnapshot(root);
    const astFiles = snapshot.files
      .filter((file) =>
        ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'].includes(
          path.extname(file.path).slice(1)
        )
      )
      .sort((left, right) => left.path.localeCompare(right.path));
    const projectHash = createHash('sha256').update('ast-project-input-v1\0');
    for (const file of astFiles)
      projectHash
        .update(file.path)
        .update('\0')
        .update(file.sha256)
        .update('\0');
    const scope = `ast-project:${snapshot.root}`;
    const taskId = `${projectHash.digest('hex')}:0`;
    const version = 'security-doctor-ast-project-v1';
    const corruptions: Array<
      (entries: Array<[string, string]>) => Array<[string, string]>
    > = [
      (entries) => entries.slice(1),
      (entries) => (entries[0] ? [entries[0], entries[0]] : []),
      (entries) =>
        entries.map(([filePath]): [string, string] => [
          filePath,
          'g'.repeat(64)
        ])
    ];

    for (const corrupt of corruptions) {
      const cache = new AnalysisResultCache();
      const cold = await runSecurityDoctor(root, {
        snapshot,
        analysisCache: cache
      });
      const cached = cache.get<{
        paths: string[];
        findings: Array<[string, unknown[]]>;
        dependencyDigests: Array<[string, string]>;
      }>(scope, taskId, version);
      expect(cached?.dependencyDigests).toHaveLength(2);
      cache.set(scope, taskId, version, {
        ...cached,
        dependencyDigests: corrupt(cached?.dependencyDigests ?? [])
      });

      const recovered = await runSecurityDoctor(root, {
        snapshot,
        analysisCache: cache
      });

      expect(recovered.cacheMetrics.astProjectMisses).toBe(1);
      expect(recovered.cacheMetrics.astProjectHits).toBe(0);
      expect(JSON.stringify(recovered.findings)).toBe(
        JSON.stringify(cold.findings)
      );
    }
  }, 30_000);

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

    expect(changed.cacheMetrics).toEqual({
      hits: 0,
      misses: 2,
      astProjectHits: 1,
      astProjectMisses: 0
    });
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
