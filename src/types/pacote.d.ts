declare module 'pacote' {
  export type PackageManifest = {
    name?: string;
    version?: string;
    deprecated?: string | boolean;
    maintainers?: Array<unknown>;
    time?: Record<string, string>;
  };

  const pacote: {
    manifest(packageName: string): Promise<PackageManifest>;
  };

  export default pacote;
}
