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
      maxResponseBytes?: number;
    } = {}
  ) {}

  async queryBatch(
    queries: OsvQuery[],
    signal?: AbortSignal
  ): Promise<OsvQueryResult[]> {
    const endpoint =
      this.options.endpoint ?? 'https://api.osv.dev/v1/querybatch';
    const timeoutMs = this.options.timeoutMs ?? 20000;
    const fetchImplementation =
      this.options.fetchImplementation ?? globalThis.fetch;
    const requestedBatchSize = this.options.batchSize ?? 500;
    const batchSize = Number.isSafeInteger(requestedBatchSize)
      ? Math.max(1, Math.min(requestedBatchSize, 500))
      : 500;
    const requestedMaximum = this.options.maxResponseBytes ?? 16 * 1024 * 1024;
    const maxResponseBytes = Number.isSafeInteger(requestedMaximum)
      ? Math.max(1_024, Math.min(requestedMaximum, 64 * 1024 * 1024))
      : 16 * 1024 * 1024;
    const results: OsvQueryResult[] = [];

    for (let start = 0; start < queries.length; start += batchSize) {
      if (signal?.aborted)
        throw new Error('OSV vulnerability lookup timed out or was cancelled.');
      const batch = queries.slice(start, start + batchSize);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      const abortFromOuter = (): void => controller.abort();
      signal?.addEventListener('abort', abortFromOuter, { once: true });
      if (signal?.aborted) abortFromOuter();

      try {
        const response = await fetchImplementation(endpoint, {
          method: 'POST',
          redirect: 'error',
          headers: {
            'content-type': 'application/json',
            'user-agent': 'toolip'
          },
          body: JSON.stringify({ queries: batch }),
          signal: controller.signal
        });

        if (!response.ok)
          throw new Error(`OSV request failed with HTTP ${response.status}.`);
        const responseBytes = await boundedResponseBytes(
          response,
          maxResponseBytes
        );
        let payload: OsvBatchResponse;
        try {
          payload = JSON.parse(
            new TextDecoder('utf-8', { fatal: true }).decode(responseBytes)
          ) as OsvBatchResponse;
        } catch {
          throw new Error('OSV returned a malformed response body.');
        }
        if (
          !payload ||
          typeof payload !== 'object' ||
          !Array.isArray(payload.results)
        )
          throw new Error('OSV returned a malformed response.');
        if (payload.results.length !== batch.length) {
          throw new Error(
            `OSV returned ${payload.results.length} results for ${batch.length} queries.`
          );
        }

        batch.forEach((query, index) => {
          const record = payload.results[index];
          if (
            !record ||
            typeof record !== 'object' ||
            (record.vulns !== undefined && !Array.isArray(record.vulns))
          )
            throw new Error('OSV returned a malformed query result.');
          const vulnerabilities = record.vulns ?? [];
          if (
            vulnerabilities.some(
              (vulnerability) =>
                !vulnerability ||
                typeof vulnerability !== 'object' ||
                typeof vulnerability.id !== 'string' ||
                !vulnerability.id.trim() ||
                (vulnerability.aliases !== undefined &&
                  (!Array.isArray(vulnerability.aliases) ||
                    vulnerability.aliases.some(
                      (alias) => typeof alias !== 'string'
                    )))
            )
          )
            throw new Error('OSV returned a malformed vulnerability record.');
          results.push({ query, vulnerabilities });
        });
      } catch (error) {
        if (error instanceof Error && error.name === 'AbortError') {
          throw new Error(
            'OSV vulnerability lookup timed out or was cancelled.'
          );
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

async function boundedResponseBytes(
  response: Response,
  maximum: number
): Promise<Uint8Array> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maximum)
    throw new Error('OSV response exceeds its byte budget.');
  if (!response.body) throw new Error('OSV response body is unavailable.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maximum)
        throw new Error('OSV response exceeds its byte budget.');
      chunks.push(next.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}
