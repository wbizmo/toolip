import type { OsvBatchResponse, OsvQuery } from './types.js';

export type OsvQueryResult = {
  query: OsvQuery;
  vulnerabilities: NonNullable<OsvBatchResponse['results'][number]['vulns']>;
};

export class OsvClient {
  constructor(
    private readonly options: {
      endpoint?: string;
      timeoutMs?: number;
      fetchImplementation?: typeof fetch;
      batchSize?: number;
    } = {}
  ) {}

  async queryBatch(queries: OsvQuery[], signal?: AbortSignal): Promise<OsvQueryResult[]> {
    const endpoint = this.options.endpoint ?? 'https://api.osv.dev/v1/querybatch';
    const timeoutMs = this.options.timeoutMs ?? 20000;
    const fetchImplementation = this.options.fetchImplementation ?? globalThis.fetch;
    const batchSize = Math.max(1, this.options.batchSize ?? 500);
    const results: OsvQueryResult[] = [];

    for (let start = 0; start < queries.length; start += batchSize) {
      const batch = queries.slice(start, start + batchSize);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      const abortFromOuter = (): void => controller.abort();
      signal?.addEventListener('abort', abortFromOuter, { once: true });

      try {
        const response = await fetchImplementation(endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'user-agent': 'toolip' },
          body: JSON.stringify({ queries: batch }),
          signal: controller.signal
        });

        if (!response.ok) throw new Error(`OSV request failed with HTTP ${response.status}.`);
        const payload = (await response.json()) as OsvBatchResponse;
        if (!Array.isArray(payload.results)) throw new Error('OSV returned a malformed response.');
        if (payload.results.length !== batch.length) {
          throw new Error(`OSV returned ${payload.results.length} results for ${batch.length} queries.`);
        }

        batch.forEach((query, index) => {
          results.push({ query, vulnerabilities: payload.results[index]?.vulns ?? [] });
        });
      } catch (error) {
        if (error instanceof Error && error.name === 'AbortError') {
          throw new Error('OSV vulnerability lookup timed out or was cancelled.');
        }
        throw error;
      } finally {
        clearTimeout(timeout);
        signal?.removeEventListener('abort', abortFromOuter);
      }
    }

    return results;
  }
}
