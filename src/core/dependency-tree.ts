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

function indexGraph(graph: NpmDependencyGraph): {
  packages: Map<string, DependencyIdentity>;
  children: Map<string, string[]>;
} {
  const packages = new Map(
    graph.packages.map((dependency) => [dependency.id, dependency])
  );
  const children = new Map<string, string[]>();

  for (const edge of graph.edges) {
    const current = children.get(edge.from) ?? [];
    if (!current.includes(edge.to)) current.push(edge.to);
    children.set(edge.from, current);
  }

  return { packages, children };
}

function treeNode(
  id: string,
  packages: Map<string, DependencyIdentity>,
  children: Map<string, string[]>,
  ancestors: Set<string>
): DependencyTreeNode | undefined {
  const dependency = packages.get(id);
  if (!dependency) return undefined;

  const nextAncestors = new Set(ancestors);
  nextAncestors.add(id);

  const nested = (children.get(id) ?? [])
    .map((childId) => {
      if (nextAncestors.has(childId)) {
        const child = packages.get(childId);
        return child
          ? {
              name: child.name,
              version: child.version,
              type: child.development ? 'devDependency' as const : 'dependency' as const,
              installPath: child.installPath,
              children: []
            }
          : undefined;
      }

      return treeNode(childId, packages, children, nextAncestors);
    })
    .filter((child): child is DependencyTreeNode => Boolean(child));

  return {
    name: dependency.name,
    version: dependency.version,
    type: dependency.development ? 'devDependency' : 'dependency',
    installPath: dependency.installPath,
    children: nested
  };
}

function graphSummary(
  children: Map<string, string[]>
): DependencyTree['summary'] {
  const direct = new Set(children.get('root') ?? []);
  const reachable = new Set<string>();
  let maxDepth = 0;

  const visit = (id: string, depth: number, ancestry: Set<string>): void => {
    reachable.add(id);
    maxDepth = Math.max(maxDepth, depth);
    if (ancestry.has(id)) return;

    const next = new Set(ancestry);
    next.add(id);
    for (const child of children.get(id) ?? []) {
      visit(child, depth + 1, next);
    }
  };

  for (const id of direct) visit(id, 1, new Set());

  return {
    direct: direct.size,
    transitive: Math.max(0, reachable.size - direct.size),
    maxDepth
  };
}

export async function buildDependencyTree(root: string): Promise<DependencyTree> {
  const graph = await readNpmDependencyGraph(root);
  const { packages, children } = indexGraph(graph);
  const dependencies = (children.get('root') ?? [])
    .map((id) => treeNode(id, packages, children, new Set()))
    .filter((dependency): dependency is DependencyTreeNode => Boolean(dependency));

  return {
    root,
    dependencies,
    summary: graphSummary(children)
  };
}
