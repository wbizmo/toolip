import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { canonicalEvidenceJson } from '../../src/core/report-signature.js';
import {
  loadWasmAnalyzerPlugin,
  loadWasmAnalyzerPluginForCli,
  runWasmAnalyzerPlugin
} from '../../src/core/analyzer-plugin.js';

const directories: string[] = [];

async function pluginFixture(
  input: {
    module?: Uint8Array;
    output?: string;
    timeoutMs?: number;
    memoryPages?: number;
    maxOutputBytes?: number;
  } = {}
) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-wasm-plugin-'));
  directories.push(root);
  const module = input.module ?? testModule({ output: input.output });
  const moduleSha256 = createHash('sha256').update(module).digest('hex');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payload = {
    schema: 'toolip.dev/analyzer-plugin/v1',
    id: 'demo-plugin',
    apiVersion: 1,
    module: 'plugin.wasm',
    moduleSha256,
    issuedAt: '2026-11-01T00:00:00.000Z',
    expiresAt: '2026-12-01T00:00:00.000Z',
    capabilities: ['read-snapshot'],
    limits: {
      timeoutMs: input.timeoutMs ?? 1_000,
      memoryPages: input.memoryPages ?? 2,
      maxInputBytes: 64 * 1024,
      maxOutputBytes: input.maxOutputBytes ?? 64 * 1024
    }
  };
  const signature = sign(
    null,
    Buffer.from(canonicalEvidenceJson(payload)),
    privateKey
  ).toString('base64');
  await writeFile(path.join(root, 'plugin.wasm'), module);
  await writeFile(
    path.join(root, 'plugin.json'),
    JSON.stringify({
      ...payload,
      signature: {
        algorithm: 'Ed25519',
        keyId: 'fixture-key',
        value: signature
      }
    })
  );
  return {
    root,
    manifest: path.join(root, 'plugin.json'),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey
  };
}

function wasmLeb(value: number): number[] {
  const bytes: number[] = [];
  let rest = value >>> 0;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (rest !== 0);
  return bytes;
}

function wasmString(value: string): number[] {
  const bytes = [...Buffer.from(value)];
  return [...wasmLeb(bytes.length), ...bytes];
}

function wasmSection(id: number, body: number[]): number[] {
  return [id, ...wasmLeb(body.length), ...body];
}

function wasmVector(items: number[][]): number[] {
  return [...wasmLeb(items.length), ...items.flat()];
}

function wasmFunction(body: number[]): number[] {
  return [...wasmLeb(body.length), ...body];
}

function testModule(
  options: {
    output?: string;
    infinite?: boolean;
    imports?: boolean;
    unboundedMemory?: boolean;
    memoryFlags?: number;
    memoryMaximum?: number;
    missingAbiExport?: boolean;
    oversizedOutput?: boolean;
    trap?: boolean;
  } = {}
): Uint8Array {
  const output = Buffer.from(
    options.output ?? JSON.stringify({ schemaVersion: 1, findings: [] })
  );
  const types = wasmSection(1, [
    ...wasmLeb(3),
    0x60,
    0x01,
    0x7f,
    0x01,
    0x7f,
    0x60,
    0x02,
    0x7f,
    0x7f,
    0x01,
    0x7f,
    0x60,
    0x00,
    0x01,
    0x7f
  ]);
  const imports = options.imports
    ? wasmSection(2, [
        ...wasmLeb(1),
        ...wasmString('env'),
        ...wasmString('open'),
        0x00,
        0x00
      ])
    : [];
  const functions = wasmSection(3, [...wasmLeb(3), 0x00, 0x01, 0x02]);
  const memoryFlags = options.memoryFlags ?? 1;
  const memoryMaximum = options.memoryMaximum ?? 2;
  const memory = options.unboundedMemory
    ? wasmSection(5, [...wasmLeb(1), 0x00, ...wasmLeb(2)])
    : wasmSection(5, [
        ...wasmLeb(1),
        ...wasmLeb(memoryFlags),
        ...wasmLeb(2),
        ...wasmLeb(memoryMaximum)
      ]);
  const indexOffset = options.imports ? 1 : 0;
  const exportItems = [
    [...wasmString('memory'), 0x02, ...wasmLeb(0)],
    [...wasmString('toolip_alloc'), 0x00, ...wasmLeb(indexOffset)],
    [...wasmString('toolip_analyze'), 0x00, ...wasmLeb(indexOffset + 1)],
    ...(!options.missingAbiExport
      ? [
          [
            ...wasmString('toolip_output_len'),
            0x00,
            ...wasmLeb(indexOffset + 2)
          ]
        ]
      : [])
  ];
  const exports = wasmSection(7, wasmVector(exportItems));
  const allocBody = wasmFunction([0x00, 0x41, 0x80, 0x10, 0x0b]);
  const analyzeBody = options.infinite
    ? wasmFunction([0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x41, 0x00, 0x0b])
    : options.trap
      ? wasmFunction([0x00, 0x00, 0x0b])
      : wasmFunction([0x00, 0x41, 0x00, 0x0b]);
  const outputLength = options.oversizedOutput ? 65_537 : output.length;
  const outputLengthBody = wasmFunction([
    0x00,
    0x41,
    ...wasmLeb(outputLength),
    0x0b
  ]);
  const code = wasmSection(10, [
    ...wasmLeb(3),
    ...allocBody,
    ...analyzeBody,
    ...outputLengthBody
  ]);
  const data = wasmSection(11, [
    ...wasmLeb(1),
    0x00,
    0x41,
    0x00,
    0x0b,
    ...wasmLeb(output.length),
    ...output
  ]);
  return new Uint8Array([
    0x00,
    0x61,
    0x73,
    0x6d,
    0x01,
    0x00,
    0x00,
    0x00,
    ...types,
    ...imports,
    ...functions,
    ...memory,
    ...exports,
    ...code,
    ...data
  ]);
}

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true }))
  );
});

describe('signed capability-limited WASM analyzer plugins', () => {
  it('resolves plugin signers from an external rotatable trust store', async () => {
    const fixture = await pluginFixture();
    const trustRoot = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-plugin-trust-')
    );
    directories.push(trustRoot);
    const storePath = path.join(trustRoot, 'plugins.json');
    await writeFile(
      storePath,
      JSON.stringify({
        version: 1,
        keys: {
          'fixture-key': {
            publicKeyPem: fixture.publicKeyPem,
            status: 'active',
            validFrom: '2026-11-01T00:00:00.000Z',
            expiresAt: '2026-12-01T00:00:00.000Z'
          }
        }
      })
    );
    const plugin = await loadWasmAnalyzerPluginForCli({
      manifestPath: fixture.manifest,
      trustStorePath: storePath,
      trustedKeyId: 'fixture-key',
      projectRoot: fixture.root,
      enabled: true
    });
    expect(plugin?.keyId).toBe('fixture-key');

    await writeFile(
      storePath,
      JSON.stringify({
        version: 1,
        keys: {
          'fixture-key': {
            publicKeyPem: fixture.publicKeyPem,
            status: 'revoked',
            revokedAt: '2026-11-10T00:00:00.000Z'
          }
        }
      })
    );
    await expect(
      loadWasmAnalyzerPluginForCli({
        manifestPath: fixture.manifest,
        trustStorePath: storePath,
        trustedKeyId: 'fixture-key',
        projectRoot: fixture.root,
        enabled: true
      })
    ).rejects.toThrow('is revoked');
  });

  it('runs a valid signed plugin and binds sanitized findings to snapshot paths', async () => {
    const output = JSON.stringify({
      schemaVersion: 1,
      findings: [
        {
          ruleId: 'TLP-PLUGIN-DEMO-PLUGIN-001',
          severity: 'high',
          confidence: 'medium',
          file: 'src/app.ts',
          line: 4,
          column: 2
        }
      ]
    });
    const fixture = await pluginFixture({ output });
    const plugin = await loadWasmAnalyzerPlugin(fixture.manifest, {
      publicKeyPem: fixture.publicKeyPem,
      trustedKeyId: 'fixture-key',
      now: Date.parse('2026-11-10T00:00:00.000Z')
    });
    expect(Reflect.has(plugin, 'moduleBytes')).toBe(false);
    const result = await runWasmAnalyzerPlugin(plugin, [
      { path: 'src/app.ts', content: 'const token = "fixture-secret-value";' }
    ]);
    expect(result.coverage.state).toBe('complete');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      source: 'signed-wasm-plugin:demo-plugin',
      message: expect.stringContaining('Review the rule definition'),
      location: { file: 'src/app.ts', line: 4, column: 2 },
      metadata: {
        pluginSha256: plugin.moduleSha256,
        pluginKeyId: 'fixture-key'
      }
    });
    expect(JSON.stringify(result.findings)).not.toContain(
      'fixture-secret-value'
    );
  });

  it('denies unsigned, changed, imported, unbounded-memory and untrusted-path plugins', async () => {
    const fixture = await pluginFixture();
    const unsignedManifest = JSON.parse(
      await readFile(fixture.manifest, 'utf8')
    ) as Record<string, unknown>;
    delete unsignedManifest.signature;
    await writeFile(fixture.manifest, JSON.stringify(unsignedManifest));
    await expect(
      loadWasmAnalyzerPlugin(fixture.manifest, {
        publicKeyPem: fixture.publicKeyPem,
        trustedKeyId: 'fixture-key'
      })
    ).rejects.toThrow('Analyzer plugin manifest is invalid');

    const changed = await pluginFixture();
    await writeFile(
      path.join(changed.root, 'plugin.wasm'),
      testModule({
        output: JSON.stringify({
          schemaVersion: 1,
          findings: [{ changed: true }]
        })
      })
    );
    await expect(
      loadWasmAnalyzerPlugin(changed.manifest, {
        publicKeyPem: changed.publicKeyPem,
        trustedKeyId: 'fixture-key'
      })
    ).rejects.toThrow('digest does not match');

    const untrusted = await pluginFixture();
    await expect(
      loadWasmAnalyzerPlugin(untrusted.manifest, {
        publicKeyPem: untrusted.publicKeyPem,
        trustedKeyId: 'wrong-key'
      })
    ).rejects.toThrow('not trusted');

    const expired = await pluginFixture();
    await expect(
      loadWasmAnalyzerPlugin(expired.manifest, {
        publicKeyPem: expired.publicKeyPem,
        trustedKeyId: 'fixture-key',
        now: Date.parse('2027-01-01T00:00:00.000Z')
      })
    ).rejects.toThrow('expired');

    const imported = await pluginFixture({
      module: testModule({ imports: true })
    });
    await expect(
      loadWasmAnalyzerPlugin(imported.manifest, {
        publicKeyPem: imported.publicKeyPem,
        trustedKeyId: 'fixture-key'
      })
    ).rejects.toThrow('imports are denied');

    const unbounded = await pluginFixture({
      module: testModule({ unboundedMemory: true })
    });
    await expect(
      loadWasmAnalyzerPlugin(unbounded.manifest, {
        publicKeyPem: unbounded.publicKeyPem,
        trustedKeyId: 'fixture-key'
      })
    ).rejects.toThrow('explicitly bounded');

    for (const memoryFlags of [3, 5]) {
      const unsupportedMemory = await pluginFixture({
        module: testModule({ memoryFlags })
      });
      await expect(
        loadWasmAnalyzerPlugin(unsupportedMemory.manifest, {
          publicKeyPem: unsupportedMemory.publicKeyPem,
          trustedKeyId: 'fixture-key'
        })
      ).rejects.toThrow('32-bit, unshared');
    }

    const excessiveMemory = await pluginFixture({
      module: testModule({ memoryMaximum: 3 }),
      memoryPages: 2
    });
    await expect(
      loadWasmAnalyzerPlugin(excessiveMemory.manifest, {
        publicKeyPem: excessiveMemory.publicKeyPem,
        trustedKeyId: 'fixture-key'
      })
    ).rejects.toThrow('exceeds the signed plugin limit');

    const unsupportedAbi = await pluginFixture({
      module: testModule({ missingAbiExport: true })
    });
    await expect(
      loadWasmAnalyzerPlugin(unsupportedAbi.manifest, {
        publicKeyPem: unsupportedAbi.publicKeyPem,
        trustedKeyId: 'fixture-key'
      })
    ).rejects.toThrow('does not implement the Toolip WASM ABI v1');
  });

  it('terminates infinite loops and rejects oversized or out-of-snapshot results as incomplete', async () => {
    const infinite = await pluginFixture({
      module: testModule({ infinite: true }),
      timeoutMs: 25
    });
    const plugin = await loadWasmAnalyzerPlugin(infinite.manifest, {
      publicKeyPem: infinite.publicKeyPem,
      trustedKeyId: 'fixture-key'
    });
    const timedOut = await runWasmAnalyzerPlugin(plugin, [
      { path: 'index.ts', content: 'export const value = 1;' }
    ]);
    expect(timedOut.coverage.state).toBe('failed');
    expect(timedOut.warnings).toContain('plugin-timeout');

    const crashing = await pluginFixture({
      module: testModule({ trap: true })
    });
    const crashingPlugin = await loadWasmAnalyzerPlugin(crashing.manifest, {
      publicKeyPem: crashing.publicKeyPem,
      trustedKeyId: 'fixture-key'
    });
    const crashed = await runWasmAnalyzerPlugin(crashingPlugin, [
      { path: 'index.ts', content: 'x' }
    ]);
    expect(crashed.coverage.state).toBe('failed');
    expect(crashed.warnings).toContain('plugin-execution-failed');

    const cancellation = new AbortController();
    const cancellablePlugin = await pluginFixture({
      module: testModule({ infinite: true }),
      timeoutMs: 5_000
    });
    const cancellable = await loadWasmAnalyzerPlugin(
      cancellablePlugin.manifest,
      {
        publicKeyPem: cancellablePlugin.publicKeyPem,
        trustedKeyId: 'fixture-key'
      }
    );
    const cancellationTimer = setTimeout(() => cancellation.abort(), 25);
    const cancelled = await runWasmAnalyzerPlugin(
      cancellable,
      [{ path: 'index.ts', content: 'x' }],
      cancellation.signal
    );
    clearTimeout(cancellationTimer);
    expect(cancelled.warnings).toContain('plugin-cancelled');

    const tooLarge = await pluginFixture({
      module: testModule({ oversizedOutput: true }),
      maxOutputBytes: 32
    });
    const bounded = await loadWasmAnalyzerPlugin(tooLarge.manifest, {
      publicKeyPem: tooLarge.publicKeyPem,
      trustedKeyId: 'fixture-key'
    });
    const oversized = await runWasmAnalyzerPlugin(bounded, [
      { path: 'index.ts', content: 'x' }
    ]);
    expect(oversized.coverage.state).toBe('failed');
    expect(oversized.warnings).toContain('plugin-execution-failed');

    const outsideOutput = JSON.stringify({
      schemaVersion: 1,
      findings: [
        {
          ruleId: 'TLP-PLUGIN-DEMO-PLUGIN-001',
          severity: 'low',
          confidence: 'low',
          file: '../outside.ts',
          line: 1,
          column: 1
        }
      ]
    });
    const outside = await pluginFixture({
      module: testModule({ output: outsideOutput })
    });
    const safe = await loadWasmAnalyzerPlugin(outside.manifest, {
      publicKeyPem: outside.publicKeyPem,
      trustedKeyId: 'fixture-key'
    });
    const invalidReference = await runWasmAnalyzerPlugin(safe, [
      { path: 'index.ts', content: 'x' }
    ]);
    expect(invalidReference.coverage.state).toBe('failed');
    expect(invalidReference.warnings).toContain(
      'plugin-output-reference-invalid'
    );
  });
});
