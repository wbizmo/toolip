import { describe, expect, it } from 'vitest';
import { IdeAnalyzerSession } from '../../src/integrations/ide/server.js';

const request = (method: string, params: unknown, id = 1) => ({
  jsonrpc: '2.0' as const, id, method, params
});

describe('IDE JSON-RPC bounded diagnostics', () => {
  it('advertises a read-only protocol with incomplete cross-file coverage', async () => {
    const session = new IdeAnalyzerSession();
    const result = await session.handle(request('initialize', {}));
    expect(result.result).toMatchObject({
      network: 'disabled', workspaceExecution: 'disabled',
      completeProjectAnalysis: false
    });
  });

  it('uses unsaved source text without project file reads and discards stale updates', async () => {
    const session = new IdeAnalyzerSession();
    expect((await session.handle(request('textDocument/didOpen', {
      path: 'src/unsafe.ts',
      version: 1,
      text: 'const data = eval("2 + 2");'
    }))).error).toBeUndefined();
    expect((await session.handle(request('textDocument/didChange', {
      path: 'src/unsafe.ts',
      version: 1,
      text: 'const data = 0;'
    }))).error?.code).toBe(-32001);
    const response = await session.handle(request('textDocument/diagnostic', {
      path: 'src/unsafe.ts'
    }));
    expect((response.result as Record<string, unknown>).version).toBe(1);
    expect((response.result as Record<string, unknown>).state).toBe('partial');
    expect(session.openDocumentCount).toBe(1);
    await session.handle(request('textDocument/didClose', { path: 'src/unsafe.ts' }));
    expect(session.retainedDocumentBytes).toBe(0);
  });

  it('rejects traversal, unsupported extensions and oversized documents', async () => {
    const session = new IdeAnalyzerSession();
    for (const candidate of [
      '../other/secrets.ts',
      '/home/customer/file.ts',
      'src/image.png',
      'C:\\Windows\\system32\\bad.js'
    ]) {
      const result = await session.handle(request('textDocument/didOpen', {
        path: candidate, version: 1, text: 'x'
      }));
      expect(result.error?.code).toBe(-32602);
    }
    expect((await session.handle(request('textDocument/didOpen', {
      path: 'src/big.ts', version: 1, text: 'a'.repeat(600 * 1024)
    }))).error?.code).toBe(-32002);
  });
});
