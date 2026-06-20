export type DependencyInfo = {
  name: string;
  version: string;
  type: 'dependency' | 'devDependency';
};

export type PackageHealth = {
  name: string;
  latestVersion: string | null;
  installedVersion: string;
  outdated: boolean;
  deprecated: boolean;
  maintainers: number;
  publishedAt: string | null;
  ageInDays: number | null;
  downloads: number | null;
  riskScore: number;
};
