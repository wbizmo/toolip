import { describe, expect, it, vi } from 'vitest';
import { OsvClient } from '../../src/providers/osv/client.js';

describe('OsvClient', () => {
  it('maps batch responses to original queries', async () => {
    const fetchImplementation = vi.fn(async () =>
      new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-test-0001' }] }] }), { status: 200 })
    ) as unknown as typeof fetch;

    const results = await new OsvClient({ fetchImplementation }).queryBatch([
      { package: { ecosystem: 'npm', name: 'example-package' }, version: '1.0.0' }
    ]);

    expect(results[0]?.vulnerabilities[0]?.id).toBe('GHSA-test-0001');
  });
});
