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
import { walkProjectFiles } from '../../src/core/file-walker.js';

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
  it('rejects duplicate pre-discovered paths instead of duplicating immutable snapshot identities', async () => {
    const root = await project();
    const files = await walkProjectFiles(root);
    expect(files).toHaveLength(1);
    const input = files[0];
    if (!input) throw new Error('missing source fixture');
    await expect(
      createProjectSnapshot(root, { discoveredFiles: [input, input] })
    ).rejects.toThrow(/duplicate.*snapshot/i);
  });

  it('enforces snapshot file count on pre-discovered entries even if discovery was performed elsewhere', async () => {
    const root = await project();
    const files = await walkProjectFiles(root);
    await expect(
      createProjectSnapshot(root, { discoveredFiles: files, maxFiles: 0 })
    ).rejects.toThrow(/snapshot.*budget/i);
  });

  it('rejects forged discovery path/identity before reusing a snapshot', async () => {
    const root = await project();
    const files = await walkProjectFiles(root);
    const first = files[0];
    if (!first) throw new Error('missing fixture file');
    const previous = await createProjectSnapshot(root, {
      discoveredFiles: files
    });
    await expect(
      createProjectSnapshot(root, {
        discoveredFiles: [
          { ...first, absolutePath: path.join(root, '..', 'fake.ts') }
        ],
        previous
      })
    ).rejects.toThrow(/discovered.*path/i);
    await expect(
      createProjectSnapshot(root, {
        discoveredFiles: [{ ...first, relativePath: '../fake.ts' }],
        previous
      })
    ).rejects.toThrow(/discovered.*path/i);
  });

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
    expect(snapshot.sourceTreeDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(snapshot.lockGraphDigest).toBe('lock');
    expect(await verifyProjectSnapshot(snapshot)).toBe(true);
    await writeFile(path.join(root, 'src', 'a.ts'), 'changed');
    expect(await verifyProjectSnapshot(snapshot)).toBe(false);
    const changed = await createProjectSnapshot(root);
    expect(changed.sourceTreeDigest).not.toBe(snapshot.sourceTreeDigest);
  });

  it('fails closed when the snapshot exceeds explicit file budgets', async () => {
    const root = await project();
    await expect(
      createProjectSnapshot(root, { maxTotalBytes: 2 })
    ).rejects.toThrow('snapshot incomplete');
  });

  it('distinguishes cancellation from an invalid snapshot during capture and verification', async () => {
    const root = await project();
    const snapshot = await createProjectSnapshot(root);
    const controller = new AbortController();
    controller.abort();
    await expect(
      createProjectSnapshot(root, { signal: controller.signal })
    ).rejects.toMatchObject({ name: 'AbortError' });
    await expect(
      verifyProjectSnapshot(snapshot, { signal: controller.signal })
    ).rejects.toMatchObject({ name: 'AbortError' });
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
    expect(cold.cacheMetrics).toMatchObject({
      hits: 0,
      misses: 2,
      astProjectHits: 0,
      astProjectMisses: 1
    });
    expect(cold.cacheMetrics.resultCache).toMatchObject({
      hits: 0,
      misses: 2,
      evictions: 0,
      entries: 3
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
    expect(warm.cacheMetrics).toMatchObject({
      hits: 2,
      misses: 0,
      astProjectHits: 1,
      astProjectMisses: 0
    });
    expect(warm.cacheMetrics.resultCache.hits).toBeGreaterThan(0);
    expect(
      warm.cacheMetrics.resultCache.retainedSerializedBytes
    ).toBeGreaterThan(0);
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
    expect(changed.cacheMetrics).toMatchObject({
      hits: 1,
      misses: 1,
      astProjectHits: 0,
      astProjectMisses: 1
    });
    expect(
      changed.cacheMetrics.resultCache.retainedSerializedBytes
    ).toBeGreaterThan(0);
    expect(changed.findings).toHaveLength(warm.findings.length);
  }, 30_000);

  it('retains unaffected AST chunks after an independent source edit', async () => {
    const root = await project();
    await writeFile(
      path.join(root, 'src', 'a.ts'),
      'export {};\neval(untrusted);\n'
    );
    for (let index = 0; index < 20; index += 1)
      await writeFile(
        path.join(
          root,
          'src',
          `independent-${String(index).padStart(2, '0')}.ts`
        ),
        `export const independent${index} = ${index};\n`
      );
    const cache = new AnalysisResultCache();
    const firstSnapshot = await createProjectSnapshot(root);
    const first = await runSecurityDoctor(root, {
      snapshot: firstSnapshot,
      analysisCache: cache
    });
    expect(first.cacheMetrics.astProjectMisses).toBe(2);
    expect(
      first.findings.some((finding) => finding.location?.file === 'src/a.ts')
    ).toBe(true);

    await writeFile(
      path.join(root, 'src', 'independent-00.ts'),
      'export const independent0 = 100;\n'
    );
    const changedSnapshot = await createProjectSnapshot(root, {
      previous: firstSnapshot
    });
    expect(changedSnapshot.metrics).toMatchObject({
      filesRead: 1,
      filesReused: 20
    });
    const changed = await runSecurityDoctor(root, {
      snapshot: changedSnapshot,
      analysisCache: cache
    });

    expect(changed.cacheMetrics.astProjectHits).toBe(1);
    expect(changed.cacheMetrics.astProjectMisses).toBe(1);
    expect(changed.findings).toEqual(first.findings);
  });

  it('invalidates importers with a changed helper and preserves unrelated components', async () => {
    const root = await project();
    for (let index = 0; index < 18; index += 1)
      await writeFile(
        path.join(
          root,
          'src',
          `a-independent-${String(index).padStart(2, '0')}.ts`
        ),
        `export const independent${index} = ${index};\n`
      );
    await writeFile(
      path.join(root, 'src', 'z-entry.ts'),
      "import { helper } from './z-helper.js';\nexport const result = helper;\n"
    );
    await writeFile(
      path.join(root, 'src', 'z-helper.ts'),
      'export const helper = 1;\n'
    );
    const cache = new AnalysisResultCache();
    const firstSnapshot = await createProjectSnapshot(root);
    const first = await runSecurityDoctor(root, {
      snapshot: firstSnapshot,
      analysisCache: cache
    });
    expect(first.cacheMetrics.astProjectMisses).toBe(2);

    await writeFile(
      path.join(root, 'src', 'z-helper.ts'),
      'export const helper = 2;\neval(untrusted);\n'
    );
    const changedSnapshot = await createProjectSnapshot(root, {
      previous: firstSnapshot
    });
    const changed = await runSecurityDoctor(root, {
      snapshot: changedSnapshot,
      analysisCache: cache
    });

    expect(changed.cacheMetrics.astProjectHits).toBe(1);
    expect(changed.cacheMetrics.astProjectMisses).toBe(1);
    expect(changed.cacheMetrics.hits).toBe(19);
    expect(changed.cacheMetrics.misses).toBe(2);
    expect(
      changed.findings.some(
        (finding) => finding.location?.file === 'src/z-helper.ts'
      )
    ).toBe(true);
    const uncached = await runSecurityDoctor(root, {
      snapshot: changedSnapshot
    });
    expect(changed.findings).toEqual(uncached.findings);
  }, 30_000);

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
    const scope = `ast-project:${snapshot.root}`;
    const taskId = createHash('sha256')
      .update('ast-project-cache-paths-v2\0')
      .update(JSON.stringify(astFiles.map((file) => file.path)))
      .digest('hex');
    const version = 'security-doctor-ast-project-v2';
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
        fingerprints: Array<[string, string]>;
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

  it('rejects truncated, duplicated, and malformed cached fingerprints', async () => {
    const root = await project();
    await writeFile(
      path.join(root, 'src', 'b.ts'),
      'export const other = 2;\n'
    );
    const snapshot = await createProjectSnapshot(root);
    const files = snapshot.files
      .filter((file) =>
        ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'].includes(
          path.extname(file.path).slice(1)
        )
      )
      .sort((left, right) => left.path.localeCompare(right.path));
    const scope = `ast-project:${snapshot.root}`;
    const taskId = createHash('sha256')
      .update('ast-project-cache-paths-v2\0')
      .update(JSON.stringify(files.map((file) => file.path)))
      .digest('hex');
    const version = 'security-doctor-ast-project-v2';
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
        fingerprints: Array<[string, string]>;
        findings: Array<[string, unknown[]]>;
        dependencyDigests: Array<[string, string]>;
      }>(scope, taskId, version);
      expect(cached?.fingerprints).toHaveLength(2);
      cache.set(scope, taskId, version, {
        ...cached,
        fingerprints: corrupt(cached?.fingerprints ?? [])
      });

      const recovered = await runSecurityDoctor(root, {
        snapshot,
        analysisCache: cache
      });

      expect(recovered.cacheMetrics.astProjectMisses).toBe(1);
      expect(recovered.cacheMetrics.astProjectHits).toBe(0);
      expect(recovered.findings).toEqual(cold.findings);
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

    expect(changed.cacheMetrics).toMatchObject({
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
