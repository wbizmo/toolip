import { describe, expect, it } from 'vitest';
import { serializeMcpOutput } from '../src/mcp/server.js';

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
});
