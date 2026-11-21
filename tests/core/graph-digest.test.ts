import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../../src/core/canonical-json.js';
import { digestDependencyGraph } from '../../src/core/dependencies/graph-digest.js';
import type { DependencyGraphDigestInput } from '../../src/core/dependencies/graph-digest.js';

function legacyDigest(graph: DependencyGraphDigestInput): string {
  const sortValues = <T>(values: readonly T[]): T[] =>
    values
      .map((value) => ({ value, canonical: canonicalJson(value) }))
      .sort((left, right) =>
        left.canonical < right.canonical
          ? -1
          : left.canonical > right.canonical
            ? 1
            : 0
      )
      .map(({ value }) => value);
  const payload = {
    schema: 'toolip.dependency-graph/v1',
    manager: graph.manager ?? null,
    complete: graph.complete,
    packages: sortValues(
      graph.packages.map((pkg) => ({
        ...pkg,
        ...(pkg.os ? { os: [...pkg.os].sort() } : {}),
        ...(pkg.cpu ? { cpu: [...pkg.cpu].sort() } : {}),
        ...(pkg.libc ? { libc: [...pkg.libc].sort() } : {}),
        ...(pkg.declaredFeatures
          ? { declaredFeatures: [...pkg.declaredFeatures].sort() }
          : {}),
        ...(pkg.activeFeatures
          ? { activeFeatures: [...pkg.activeFeatures].sort() }
          : {})
      }))
    ),
    edges: sortValues(
      graph.edges.map((edge) => ({
        ...edge,
        ...(edge.extras ? { extras: [...edge.extras].sort() } : {}),
        ...(edge.requestedFeatures
          ? { requestedFeatures: [...edge.requestedFeatures].sort() }
          : {})
      }))
    ),
    unresolvedDependencies: sortValues(graph.unresolvedDependencies ?? []),
    warnings: [...graph.warnings].sort()
  };
  return createHash('sha256')
    .update('toolip-dependency-graph-v1\0')
    .update(canonicalJson(payload))
    .digest('hex');
}

describe('dependency graph digest', () => {
  it('preserves the prior canonical digest for ordinary graphs', () => {
    const graph: DependencyGraphDigestInput = {
      manager: 'npm',
      complete: false,
      packages: [
        {
          id: 'npm:z',
          ecosystem: 'npm',
          name: 'z',
          version: '1.0.0',
          direct: true,
          development: false,
          source: 'fixture',
          installPath: 'node_modules/z',
          os: ['win32', 'linux']
        }
      ],
      edges: [
        {
          from: 'root',
          to: 'npm:z',
          name: 'z',
          requirement: '^1.0.0',
          section: 'dependency'
        }
      ],
      unresolvedDependencies: [],
      warnings: ['second', 'first']
    };

    expect(digestDependencyGraph(graph)).toBe(legacyDigest(graph));
  });

  it('digests a 50k-node converging graph beyond the generic JSON node cap', () => {
    const packageCount = 25_000;
    const packages = Array.from({ length: packageCount }, (_, index) => ({
      id: `npm:${index}`,
      ecosystem: 'npm' as const,
      name: `package-${index}`,
      version: '1.0.0',
      direct: index < 2,
      development: false,
      source: 'fixture',
      installPath: `node_modules/package-${index}`
    }));
    const edges = Array.from({ length: packageCount * 2 }, (_, index) => ({
      from: `npm:${index % packageCount}`,
      to: `npm:${(index + 1) % packageCount}`,
      name: `package-${(index + 1) % packageCount}`,
      requirement: '*',
      section: 'dependency' as const
    }));
    const digest = digestDependencyGraph({
      manager: 'npm',
      complete: true,
      packages,
      edges,
      unresolvedDependencies: [],
      warnings: []
    });

    expect(digest).toMatch(/^[a-f0-9]{64}$/u);
  }, 30_000);
});
