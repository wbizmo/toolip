import type { AnalyzerCache } from '../contracts/analyzer.js';

type CacheEntry = {
  value: unknown;
  expiresAt?: number;
};

export class MemoryCache implements AnalyzerCache {
  private readonly entries = new Map<string, CacheEntry>();

  async get<T>(key: string): Promise<T | undefined> {
    const entry = this.entries.get(key);

    if (!entry) {
      return undefined;
    }

    if (
      entry.expiresAt !== undefined &&
      entry.expiresAt <= Date.now()
    ) {
      this.entries.delete(key);
      return undefined;
    }

    return entry.value as T;
  }

  async set<T>(
    key: string,
    value: T,
    ttlMs?: number
  ): Promise<void> {
    this.entries.set(key, {
      value,
      expiresAt:
        ttlMs === undefined ? undefined : Date.now() + ttlMs
    });
  }

  clear(): void {
    this.entries.clear();
  }
}
