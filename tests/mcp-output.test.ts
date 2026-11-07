import { describe, expect, it } from 'vitest';
import {
  boundedMcpTextResponse,
  McpBudgetError,
  McpResourceBudget,
  isMcpToolAuthorized,
  mcpToolCapabilities,
  resolveMcpCapabilities,
  serializeMcpOutput
} from '../src/mcp/server.js';

describe('MCP output sanitization', () => {
  it('redacts non-HTTP URL userinfo and preserves distinct finding identifiers', () => {
    const output = serializeMcpOutput({
      error:
        'git provider failed at git+ssh://alice:provider-secret@git.example/repo',
      findings: [
        { id: 'TLP-SECRET-PASSWORD:config.ts:10:2' },
        { id: 'TLP-SECRET-PASSWORD:config.ts:11:2' }
      ]
    });

    expect(output).toContain('git+ssh://[redacted]@git.example/repo');
    expect(output).not.toContain('provider-secret');
    expect(output).toContain('TLP-SECRET-PASSWORD:config.ts:10:2');
    expect(output).toContain('TLP-SECRET-PASSWORD:config.ts:11:2');
  });

  it('defaults unsafe capabilities off and fails explicitly on oversized output', async () => {
    const capabilities = resolveMcpCapabilities();
    expect(capabilities['external-network']).toBe(false);
    expect(capabilities['write-reports']).toBe(false);
    expect(capabilities['create-pr']).toBe(false);
    expect(capabilities['vault-access']).toBe(false);
    const result = await boundedMcpTextResponse(
      { value: 'x'.repeat(2_000) },
      1_024
    );
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain('MCP_RESPONSE_LIMIT');
    await expect(boundedMcpTextResponse({}, 0)).rejects.toThrow(
      '1 KiB and 16 MiB'
    );
  });

  it('attaches validated request identifiers to bounded success and failure output', async () => {
    expect(
      await boundedMcpTextResponse({ status: 'complete' }, 1_024, 'request-7')
    ).toMatchObject({ _meta: { 'toolip/requestId': 'request-7' } });
    expect(
      await boundedMcpTextResponse(
        { status: 'complete' },
        1_024,
        'x'.repeat(129)
      )
    ).not.toHaveProperty('_meta');
  });

  it('stops at the byte budget before inspecting later output properties', async () => {
    let getterCalls = 0;
    const value = {
      oversized: 'x'.repeat(2_000),
      get later() {
        getterCalls++;
        return 'must not be read';
      }
    };

    const response = await boundedMcpTextResponse(value, 1_024);
    expect(response.isError).toBe(true);
    expect(JSON.stringify(response)).toContain('MCP_RESPONSE_LIMIT');
    expect(getterCalls).toBe(0);
  });

  it('cancels bounded response serialization while traversing a large result', async () => {
    const controller = new AbortController();
    setImmediate(() => controller.abort());
    await expect(
      boundedMcpTextResponse(
        Array.from({ length: 2_000 }, () => 'safe'),
        1_024_000,
        undefined,
        controller.signal
      )
    ).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('keeps an explicit capability requirement for every registered read tool', () => {
    expect(Object.keys(mcpToolCapabilities).sort()).toEqual([
      'toolip_diff',
      'toolip_doctor',
      'toolip_policy_check',
      'toolip_sbom'
    ]);
    const defaults = resolveMcpCapabilities();
    for (const requirements of Object.values(mcpToolCapabilities)) {
      expect(Object.isFrozen(requirements)).toBe(true);
    }
    for (const tool of Object.keys(mcpToolCapabilities) as Array<
      keyof typeof mcpToolCapabilities
    >) {
      expect(isMcpToolAuthorized(tool, defaults)).toBe(true);
      for (const capability of mcpToolCapabilities[tool]) {
        expect(
          isMcpToolAuthorized(tool, { ...defaults, [capability]: false })
        ).toBe(false);
      }
    }
  });

  it('rejects unknown, non-boolean and non-plain capability configuration', () => {
    expect(() =>
      resolveMcpCapabilities({ 'external-network': 'yes' } as never)
    ).toThrow('must be boolean');
    expect(() =>
      resolveMcpCapabilities({ 'vault-access': true, unsafe: true } as never)
    ).toThrow('Unknown MCP capability');
    expect(() =>
      resolveMcpCapabilities(
        Object.create({ 'external-network': true }) as never
      )
    ).toThrow('plain object');
  });

  it('rejects capability accessors without executing them', () => {
    let getterCalls = 0;
    const capabilities = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(capabilities, 'external-network', {
      enumerable: true,
      get() {
        getterCalls++;
        return true;
      }
    });

    expect(() => resolveMcpCapabilities(capabilities as never)).toThrow(
      'must be a data property'
    );
    expect(getterCalls).toBe(0);
  });

  it('rejects unbounded process-level call, concurrency and timeout budgets', () => {
    expect(
      () =>
        new McpResourceBudget({
          maxConcurrentTools: 33,
          maxToolCalls: 1,
          toolTimeoutMs: 1
        })
    ).toThrow('outside the supported limits');
    expect(
      () =>
        new McpResourceBudget({
          maxConcurrentTools: 1,
          maxToolCalls: 100_001,
          toolTimeoutMs: 1
        })
    ).toThrow('outside the supported limits');
    expect(
      () =>
        new McpResourceBudget({
          maxConcurrentTools: 1,
          maxToolCalls: 1,
          toolTimeoutMs: 900_001
        })
    ).toThrow('outside the supported limits');
  });

  it('enforces concurrent and total call limits and reclaims completed capacity', async () => {
    const budget = new McpResourceBudget({
      maxConcurrentTools: 1,
      maxToolCalls: 3,
      toolTimeoutMs: 500
    });
    let finish: (() => void) | undefined;
    const active = budget.run(
      () => new Promise<void>((resolve) => (finish = resolve))
    );
    await expect(budget.run(async () => undefined)).rejects.toMatchObject({
      code: 'MCP_CONCURRENCY_LIMIT'
    });
    finish?.();
    await active;
    await expect(budget.run(async () => 'ok')).resolves.toBe('ok');
    await expect(budget.run(async () => 'never')).rejects.toBeInstanceOf(
      McpBudgetError
    );
  });

  it('returns on timeout, aborts cooperative work, and retains capacity for a zombie task', async () => {
    const budget = new McpResourceBudget({
      maxConcurrentTools: 1,
      maxToolCalls: 4,
      toolTimeoutMs: 5
    });
    let signal: AbortSignal | undefined;
    await expect(
      budget.run(async (value) => {
        signal = value;
        return await new Promise<never>(() => undefined);
      })
    ).rejects.toMatchObject({ code: 'MCP_TIMEOUT' });
    expect(signal?.aborted).toBe(true);
    await expect(budget.run(async () => 'blocked')).rejects.toMatchObject({
      code: 'MCP_CONCURRENCY_LIMIT'
    });
  });

  it('does not start queued work when the client aborts before the operation runs', async () => {
    const budget = new McpResourceBudget({
      maxConcurrentTools: 1,
      maxToolCalls: 1,
      toolTimeoutMs: 500
    });
    const controller = new AbortController();
    let started = false;
    const pending = budget.run(async () => {
      started = true;
      return 'unexpected';
    }, controller.signal);

    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: 'MCP_CANCELLED' });
    await Promise.resolve();
    expect(started).toBe(false);
  });
});
