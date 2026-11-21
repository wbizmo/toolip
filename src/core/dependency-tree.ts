import {
  readNpmDependencyGraph,
  type DependencyIdentity,
  type NpmDependencyGraph
} from './dependencies/inventory.js';

export type DependencyTreeNode = {
  name: string;
  version: string;
  type: 'dependency' | 'devDependency';
  installPath: string;
  children: DependencyTreeNode[];
  /** A shared or cyclic node already expanded elsewhere in the graph. */
  referenceOnly?: true;
};

export type DependencyTree = {
  root: string;
  dependencies: DependencyTreeNode[];
  summary: {
    direct: number;
    transitive: number;
    maxDepth: number;
  };
};

/** @internal Counters used to verify graph traversal resource bounds. */
export type DependencyGraphTraversalStats = {
  enqueuedNodes: number;
  peakQueueEntries: number;
};

function indexGraph(graph: NpmDependencyGraph): {
  packages: Map<string, DependencyIdentity>;
  children: Map<string, string[]>;
} {
  const packages = new Map(
    graph.packages.map((dependency) => [dependency.id, dependency])
  );
  const children = new Map<string, string[]>();
  const childSets = new Map<string, Set<string>>();

  for (const edge of graph.edges) {
    const current = children.get(edge.from) ?? [];
    const seen = childSets.get(edge.from) ?? new Set<string>();
    if (!seen.has(edge.to)) {
      seen.add(edge.to);
      current.push(edge.to);
    }
    childSets.set(edge.from, seen);
    children.set(edge.from, current);
  }

  return { packages, children };
}

function treeNode(
  id: string,
  packages: Map<string, DependencyIdentity>,
  children: Map<string, string[]>,
  expanded: Set<string>
): DependencyTreeNode | undefined {
  const dependency = packages.get(id);
  if (!dependency) return undefined;
  const rootNode: DependencyTreeNode = {
    name: dependency.name,
    version: dependency.version,
    type: dependency.development ? 'devDependency' : 'dependency',
    installPath: dependency.installPath,
    children: []
  };
  if (expanded.has(id)) {
    rootNode.referenceOnly = true;
    return rootNode;
  }
  expanded.add(id);

  const stack: Array<{ id: string; node: DependencyTreeNode }> = [
    { id, node: rootNode }
  ];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    for (const childId of children.get(current.id) ?? []) {
      const child = packages.get(childId);
      if (!child) continue;
      const childNode: DependencyTreeNode = {
        name: child.name,
        version: child.version,
        type: child.development ? 'devDependency' : 'dependency',
        installPath: child.installPath,
        children: []
      };
      current.node.children.push(childNode);
      if (expanded.has(childId)) {
        childNode.referenceOnly = true;
        continue;
      }
      expanded.add(childId);
      stack.push({ id: childId, node: childNode });
    }
  }
  return rootNode;
}

export function graphSummary(
  children: ReadonlyMap<string, readonly string[]>,
  stats?: DependencyGraphTraversalStats
): DependencyTree['summary'] {
  const direct = new Set(children.get('root') ?? []);
  const reachable = new Set(direct);
  const queue = [...direct];
  if (stats) {
    stats.enqueuedNodes = queue.length;
    stats.peakQueueEntries = queue.length;
  }
  for (let cursor = 0; cursor < queue.length; cursor++) {
    const current = queue[cursor];
    if (!current) continue;
    for (const child of children.get(current) ?? []) {
      if (reachable.has(child)) continue;
      reachable.add(child);
      queue.push(child);
      if (stats) {
        stats.enqueuedNodes += 1;
        stats.peakQueueEntries = Math.max(
          stats.peakQueueEntries,
          queue.length - cursor - 1
        );
      }
    }
  }

  const indegree = new Map([...reachable].map((id) => [id, 0]));
  for (const id of reachable) {
    for (const child of children.get(id) ?? []) {
      if (reachable.has(child)) {
        indegree.set(child, (indegree.get(child) ?? 0) + 1);
      }
    }
  }
  const depths = new Map([...direct].map((id) => [id, 1]));
  const ready = [...reachable].filter((id) => indegree.get(id) === 0);
  let processed = 0;
  let longestDagDepth = 0;
  for (let cursor = 0; cursor < ready.length; cursor++) {
    const id = ready[cursor];
    if (!id) continue;
    processed += 1;
    const depth = depths.get(id) ?? 1;
    longestDagDepth = Math.max(longestDagDepth, depth);
    for (const child of children.get(id) ?? []) {
      if (!reachable.has(child)) continue;
      depths.set(child, Math.max(depths.get(child) ?? 0, depth + 1));
      const remaining = (indegree.get(child) ?? 1) - 1;
      indegree.set(child, remaining);
      if (remaining === 0) ready.push(child);
    }
  }

  // Longest simple path is intractable on arbitrary cyclic graphs. Keep cycle
  // handling bounded and use the maximum shortest root distance in that case.
  let maxDepth = longestDagDepth;
  if (processed !== reachable.size) {
    maxDepth = 0;
    const distances = new Map([...direct].map((id) => [id, 1]));
    const breadthFirst = [...direct];
    for (let cursor = 0; cursor < breadthFirst.length; cursor++) {
      const id = breadthFirst[cursor];
      if (!id) continue;
      const depth = distances.get(id) ?? 1;
      maxDepth = Math.max(maxDepth, depth);
      for (const child of children.get(id) ?? []) {
        if (!reachable.has(child) || distances.has(child)) continue;
        distances.set(child, depth + 1);
        breadthFirst.push(child);
      }
    }
  }

  return {
    direct: direct.size,
    transitive: Math.max(0, reachable.size - direct.size),
    maxDepth
  };
}

export async function buildDependencyTree(
  root: string
): Promise<DependencyTree> {
  const graph = await readNpmDependencyGraph(root);
  if (!graph.complete) {
    throw new Error(
      `Dependency tree is incomplete: ${graph.warnings.slice(0, 5).join('; ')}`
    );
  }
  const { packages, children } = indexGraph(graph);
  const expanded = new Set<string>();
  const dependencies = (children.get('root') ?? [])
    .map((id) => treeNode(id, packages, children, expanded))
    .filter((dependency): dependency is DependencyTreeNode =>
      Boolean(dependency)
    );

  return {
    root,
    dependencies,
    summary: graphSummary(children)
  };
}
