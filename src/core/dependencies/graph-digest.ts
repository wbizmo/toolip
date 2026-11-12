import { createHash } from 'node:crypto';
import { canonicalJson } from '../canonical-json.js';
import type {
  DependencyEdge,
  DependencyIdentity,
  UnresolvedDependencyEdge
} from './inventory.js';

export type DependencyGraphDigestInput = Readonly<{
  manager?: string;
  complete: boolean;
  packages: readonly DependencyIdentity[];
  edges: readonly DependencyEdge[];
  unresolvedDependencies?: readonly UnresolvedDependencyEdge[];
  warnings: readonly string[];
}>;

function sortedCanonicalValues<T>(values: readonly T[]): T[] {
  return values
    .map((value) => ({ value, canonical: canonicalJson(value) }))
    .sort((left, right) =>
      left.canonical < right.canonical
        ? -1
        : left.canonical > right.canonical
          ? 1
          : 0
    )
    .map(({ value }) => value);
}

/** Stable digest of resolved identities, graph edges, unresolved declarations and warnings. */
export function digestDependencyGraph(
  graph: DependencyGraphDigestInput
): string {
  const packages = graph.packages.map((pkg) => ({
    ...pkg,
    ...(pkg.os ? { os: [...pkg.os].sort() } : {}),
    ...(pkg.cpu ? { cpu: [...pkg.cpu].sort() } : {}),
    ...(pkg.libc ? { libc: [...pkg.libc].sort() } : {}),
    ...(pkg.declaredFeatures
      ? { declaredFeatures: [...pkg.declaredFeatures].sort() }
      : {})
  }));
  const edges = graph.edges.map((edge) => ({
    ...edge,
    ...(edge.extras ? { extras: [...edge.extras].sort() } : {}),
    ...(edge.requestedFeatures
      ? { requestedFeatures: [...edge.requestedFeatures].sort() }
      : {})
  }));
  const payload = {
    schema: 'toolip.dependency-graph/v1',
    manager: graph.manager ?? null,
    complete: graph.complete,
    packages: sortedCanonicalValues(packages),
    edges: sortedCanonicalValues(edges),
    unresolvedDependencies: sortedCanonicalValues(
      graph.unresolvedDependencies ?? []
    ),
    warnings: [...graph.warnings].sort()
  };
  return createHash('sha256')
    .update('toolip-dependency-graph-v1\0')
    .update(canonicalJson(payload))
    .digest('hex');
}
