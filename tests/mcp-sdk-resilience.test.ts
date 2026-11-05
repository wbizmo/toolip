import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

const connections: Array<{ client: Client; server: McpServer }> = [];

afterEach(async () => {
  for (const { client, server } of connections.splice(0)) {
    await client.close();
    await server.close();
  }
});

async function createPair() {
  const server = new McpServer(
    { name: 'toolip-resilience-test', version: '0.0.0' },
    { maxToolInputElements: 32 }
  );
  let handlerSignal: AbortSignal | undefined;
  server.registerTool(
    'probe',
    {
      inputSchema: z.object({ value: z.string().max(64).optional() }).strict()
    },
    async (_args, extra) => {
      handlerSignal = extra.signal;
      if (_args.value === 'pending') {
        await new Promise<void>((resolve) => {
          if (extra.signal.aborted) resolve();
          else
            extra.signal.addEventListener('abort', () => resolve(), {
              once: true
            });
        });
      }
      return { content: [{ type: 'text', text: 'settled' }] };
    }
  );
  const client = new Client({
    name: 'toolip-resilience-test',
    version: '0.0.0'
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await Promise.all([
    client.connect(clientTransport),
    server.connect(serverTransport)
  ]);
  const pair = { client, server, getHandlerSignal: () => handlerSignal };
  connections.push(pair);
  return pair;
}

describe('MCP SDK adversarial input and cancellation behavior (#50)', () => {
  it('rejects deterministic malformed and oversized payloads, then remains usable', async () => {
    const { client } = await createPair();
    const malformed: unknown[] = [
      null,
      [],
      { value: 1 },
      { value: 'x'.repeat(65) },
      { value: 'ok', extra: true },
      Object.fromEntries(
        Array.from({ length: 40 }, (_, index) => [`k${index}`, index])
      )
    ];

    for (const argument of malformed) {
      const outcome = await client
        .callTool({
          name: 'probe',
          arguments: argument as Record<string, unknown>
        })
        .then(
          (result) => result,
          (error: unknown) => ({ error })
        );
      expect(Boolean('error' in outcome || outcome.isError)).toBe(true);
    }
    await expect(
      client.callTool({ name: 'probe', arguments: { value: 'valid' } })
    ).resolves.toMatchObject({
      content: [{ text: 'settled' }]
    });
  });

  it('propagates a client AbortSignal into the server handler and settles it', async () => {
    const { client, getHandlerSignal } = await createPair();
    const controller = new AbortController();
    const request = client.callTool(
      { name: 'probe', arguments: { value: 'pending' } },
      undefined,
      { signal: controller.signal }
    );

    await vi.waitFor(() => expect(getHandlerSignal()).toBeDefined());
    controller.abort(new Error('test cancellation'));

    await expect(request).rejects.toMatchObject({ code: -32001 });
    await vi.waitFor(() => expect(getHandlerSignal()?.aborted).toBe(true));
  });
});
