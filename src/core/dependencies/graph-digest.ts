import { createHash } from 'node:crypto';
import { canonicalJson } from '../canonical-json.js';
import type {
  DependencyEdge,
  DependencyIdentity,
  UnresolvedDependencyEdge
} from './inventory.js';

// The post-merge qualification ceiling contains up to 250k exact package
// instances and a bounded fan-out graph. Canonical strings are still capped
// independently from the three-million-item limit before hashing.
const maximumGraphDigestBytes = 256 * 1024 * 1024;
// Supports the 250k-package qualification fixture at fan-out eight, plus
// package and edge identities, while remaining a fixed hard ceiling.
const maximumGraphDigestItems = 3_000_000;
type DigestBudget = { bytes: number; items: number };

export type DependencyGraphDigestInput = Readonly<{
  manager?: string;
  complete: boolean;
  packages: readonly DependencyIdentity[];
  edges: readonly DependencyEdge[];
  unresolvedDependencies?: readonly UnresolvedDependencyEdge[];
  warnings: readonly string[];
}>;

function reserve(budget: DigestBudget, text: string): void {
  budget.bytes += Buffer.byteLength(text, 'utf8');
  if (budget.bytes > maximumGraphDigestBytes)
    throw new RangeError('Dependency graph digest exceeds its byte limit.');
}

function canonicalItems<T>(
  values: readonly T[],
  normalize: (value: T) => unknown,
  budget: DigestBudget
): string[] {
  if (values.length > maximumGraphDigestItems - budget.items)
    throw new RangeError('Dependency graph digest exceeds its item limit.');
  budget.items += values.length;
  reserve(budget, '[]');
  const result: string[] = [];
  for (const value of values) {
    const encoded = canonicalJson(normalize(value));
    reserve(budget, encoded);
    result.push(encoded);
  }
  if (result.length > 1) reserve(budget, ','.repeat(result.length - 1));
  result.sort();
  return result;
}

function writeCanonicalArray(
  hash: ReturnType<typeof createHash>,
  values: readonly string[]
): void {
  hash.update('[');
  for (let index = 0; index < values.length; index += 1) {
    if (index > 0) hash.update(',');
    hash.update(values[index] ?? 'null');
  }
  hash.update(']');
}

/** Stable digest of resolved identities, graph edges, unresolved declarations and warnings. */
export function digestDependencyGraph(
  graph: DependencyGraphDigestInput
): string {
  const budget: DigestBudget = { bytes: 0, items: 0 };
  const packages = canonicalItems(
    graph.packages,
    (pkg) => ({
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
    }),
    budget
  );
  const edges = canonicalItems(
    graph.edges,
    (edge) => ({
      ...edge,
      ...(edge.extras ? { extras: [...edge.extras].sort() } : {}),
      ...(edge.requestedFeatures
        ? { requestedFeatures: [...edge.requestedFeatures].sort() }
        : {})
    }),
    budget
  );
  const unresolvedDependencies = canonicalItems(
    graph.unresolvedDependencies ?? [],
    (value) => value,
    budget
  );
  const warnings = [...graph.warnings].sort().map((warning) => {
    const encoded = canonicalJson(warning);
    reserve(budget, encoded);
    return encoded;
  });
  budget.items += warnings.length;
  if (budget.items > maximumGraphDigestItems)
    throw new RangeError('Dependency graph digest exceeds its item limit.');
  reserve(budget, '[]');
  if (warnings.length > 1) reserve(budget, ','.repeat(warnings.length - 1));

  const manager = canonicalJson(graph.manager ?? null);
  const complete = canonicalJson(graph.complete);
  const schema = canonicalJson('toolip.dependency-graph/v1');
  reserve(budget, `{"complete":${complete},"edges":`);
  reserve(budget, `,"manager":${manager},"packages":`);
  reserve(budget, `,"schema":${schema},"unresolvedDependencies":`);
  reserve(budget, ',"warnings":}');
  const hash = createHash('sha256').update('toolip-dependency-graph-v1\0');
  hash.update('{"complete":');
  hash.update(complete);
  hash.update(',"edges":');
  writeCanonicalArray(hash, edges);
  hash.update(',"manager":');
  hash.update(manager);
  hash.update(',"packages":');
  writeCanonicalArray(hash, packages);
  hash.update(',"schema":');
  hash.update(schema);
  hash.update(',"unresolvedDependencies":');
  writeCanonicalArray(hash, unresolvedDependencies);
  hash.update(',"warnings":');
  writeCanonicalArray(hash, warnings);
  hash.update('}');
  return hash.digest('hex');
}
