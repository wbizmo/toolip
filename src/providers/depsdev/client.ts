export type DepsDevVersionResponse = {
  versionKey?: {
    system?: string;
    name?: string;
    version?: string;
  };
  publishedAt?: string;
  isDefault?: boolean;
  isDeprecated?: boolean;
  deprecatedReason?: string;
  licenses?: string[];
  advisoryKeys?: Array<{
    id?: string;
  }>;
  links?: Array<{
    label?: string;
    url?: string;
  }>;
  slsaProvenances?: Array<{
    sourceRepository?: string;
    commit?: string;
    url?: string;
    verified?: boolean;
  }>;
  attestations?: Array<{
    type?: string;
    url?: string;
    verified?: boolean;
    sourceRepository?: string;
    commit?: string;
  }>;
  registries?: string[];
  relatedProjects?: Array<{
    projectKey?: {
      id?: string;
    };
    relationType?: string;
    relationProvenance?: string;
  }>;
};

export type DepsDevDependenciesResponse = {
  nodes?: Array<{
    versionKey?: {
      system?: string;
      name?: string;
      version?: string;
    };
    relation?: string;
    errors?: string[];
  }>;
  edges?: Array<{
    fromNode?: number;
    toNode?: number;
    requirement?: string;
  }>;
  error?: string;
};

export type DepsDevClientOptions = {
  endpoint?: string;
  timeoutMs?: number;
  fetchImplementation?: typeof fetch;
};

export class DepsDevClient {
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly fetchImplementation: typeof fetch;

  constructor(options: DepsDevClientOptions = {}) {
    this.endpoint =
      options.endpoint ?? 'https://api.deps.dev/v3';
    this.timeoutMs = options.timeoutMs ?? 20_000;
    this.fetchImplementation =
      options.fetchImplementation ?? globalThis.fetch;
  }

  async getVersion(
    packageName: string,
    version: string,
    signal?: AbortSignal
  ): Promise<DepsDevVersionResponse> {
    return this.getJson<DepsDevVersionResponse>(
      `/systems/npm/packages/${encodeURIComponent(
        packageName
      )}/versions/${encodeURIComponent(version)}`,
      signal
    );
  }

  async getDependencies(
    packageName: string,
    version: string,
    signal?: AbortSignal
  ): Promise<DepsDevDependenciesResponse> {
    return this.getJson<DepsDevDependenciesResponse>(
      `/systems/npm/packages/${encodeURIComponent(
        packageName
      )}/versions/${encodeURIComponent(
        version
      )}:dependencies`,
      signal
    );
  }

  private async getJson<T>(
    pathname: string,
    outerSignal?: AbortSignal
  ): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      this.timeoutMs
    );

    const abort = (): void => controller.abort();
    outerSignal?.addEventListener(
      'abort',
      abort,
      {
        once: true
      }
    );

    try {
      const response =
        await this.fetchImplementation(
          `${this.endpoint}${pathname}`,
          {
            headers: {
              accept: 'application/json',
              'user-agent': 'toolip'
            },
            signal: controller.signal
          }
        );

      if (!response.ok) {
        throw new Error(
          `deps.dev request failed with HTTP ${response.status}.`
        );
      }

      return (await response.json()) as T;
    } finally {
      clearTimeout(timeout);
      outerSignal?.removeEventListener(
        'abort',
        abort
      );
    }
  }
}
