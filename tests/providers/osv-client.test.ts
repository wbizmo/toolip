import { describe, expect, it, vi } from 'vitest';
import { OsvClient } from '../../src/providers/osv/client.js';

describe('OsvClient', () => {
  it('maps batch responses to original queries', async () => {
    const fetchImplementation = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-test-0001' }] }] }),
          { status: 200 }
        )
    ) as unknown as typeof fetch;

    const results = await new OsvClient({ fetchImplementation }).queryBatch([
      {
        package: { ecosystem: 'npm', name: 'example-package' },
        version: '1.0.0'
      }
    ]);

    expect(results[0]?.vulnerabilities[0]?.id).toBe('GHSA-test-0001');
  });

  it('rejects oversized OSV response bodies before parsing JSON', async () => {
    const oversized = new Response('x'.repeat(2_048), { status: 200 });
    const client = new OsvClient({
      maxResponseBytes: 1_024,
      fetchImplementation: (async () => oversized) as typeof fetch
    });

    await expect(
      client.queryBatch([
        {
          package: { ecosystem: 'npm', name: 'example-package' },
          version: '1.0.0'
        }
      ])
    ).rejects.toThrow('OSV response exceeds its byte budget');
  });

  it('rejects a declared oversized response and preserves exact result counts', async () => {
    const declaredOversize = new OsvClient({
      maxResponseBytes: 1_024,
      fetchImplementation: (async () =>
        new Response('{}', {
          status: 200,
          headers: { 'content-length': '2048' }
        })) as typeof fetch
    });
    await expect(
      declaredOversize.queryBatch([
        {
          package: { ecosystem: 'npm', name: 'example-package' },
          version: '1.0.0'
        }
      ])
    ).rejects.toThrow('OSV response exceeds its byte budget');

    const wrongCount = new OsvClient({
      fetchImplementation: (async () =>
        new Response(JSON.stringify({ results: [] }), {
          status: 200
        })) as typeof fetch
    });
    await expect(
      wrongCount.queryBatch([
        {
          package: { ecosystem: 'npm', name: 'example-package' },
          version: '1.0.0'
        }
      ])
    ).rejects.toThrow('returned 0 results for 1 queries');
  });

  it('does not send queries when the caller cancelled before the batch began', async () => {
    const fetchImplementation = vi.fn(
      async () =>
        new Response(JSON.stringify({ results: [{ vulns: [] }] }), {
          status: 200
        })
    ) as unknown as typeof fetch;
    const controller = new AbortController();
    controller.abort();

    await expect(
      new OsvClient({ fetchImplementation }).queryBatch(
        [
          {
            package: { ecosystem: 'npm', name: 'example-package' },
            version: '1.0.0'
          }
        ],
        controller.signal
      )
    ).rejects.toThrow('timed out or was cancelled');
    expect(fetchImplementation).not.toHaveBeenCalled();
  });
});
