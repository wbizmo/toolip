declare module 'pacote' {
  export type PackageManifest = {
    name?: string;
    version?: string;
    deprecated?: string | boolean;
    maintainers?: Array<unknown>;
    time?: Record<string, string>;
  };

  /** Subset of pacote/npm-registry-fetch options Toolip relies on. */
  export type ManifestOptions = {
    /** Always pin public metadata lookups to the public npm registry. */
    registry?: string;
    signal?: AbortSignal;
    /** Per-request timeout in ms. */
    timeout?: number;
    /** Library-level retries; Toolip sets 0 and applies its own bounded policy. */
    fetchRetries?: number;
  };

  const pacote: {
    manifest(
      packageName: string,
      options?: ManifestOptions
    ): Promise<PackageManifest>;
  };

  export default pacote;
}
