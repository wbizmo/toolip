import { readDependencies } from './read-dependencies.js';

export type DependencyTreeNode = {
  name: string;
  version: string;
  type: 'dependency' | 'devDependency';
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

export async function buildDependencyTree(root: string): Promise<DependencyTree> {
  const dependencies = await readDependencies(root);

  return {
    root,
    dependencies: dependencies.map((dependency) => ({
      name: dependency.name,
      version: dependency.version,
      type: dependency.type,
      children: []
    })),
    summary: {
      direct: dependencies.length,
      transitive: 0,
      maxDepth: dependencies.length > 0 ? 1 : 0
    }
  };
}
