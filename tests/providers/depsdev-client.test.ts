import { describe, expect, it, vi } from 'vitest';
import { DepsDevClient } from '../../src/providers/depsdev/client.js';

describe('DepsDevClient', () => {
  it('encodes npm package names and versions', async () => {
    const fetchImplementation = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            licenses: ['MIT']
          }),
          {
            status: 200
          }
        )
    ) as unknown as typeof fetch;

    const client = new DepsDevClient({
      fetchImplementation
    });

    const result = await client.getVersion(
      '@scope/package',
      '1.0.0'
    );

    expect(result.licenses).toEqual(['MIT']);
    expect(fetchImplementation).toHaveBeenCalledWith(
      expect.stringContaining(
        '%40scope%2Fpackage/versions/1.0.0'
      ),
      expect.any(Object)
    );
  });
});
