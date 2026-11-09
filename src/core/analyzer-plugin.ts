import { constants } from 'node:fs';
import { createHash, verify as cryptoVerify } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { z } from 'zod';
import { coverageOf, type AnalysisCoverage } from '../contracts/analysis.js';
import type { Finding } from '../contracts/finding.js';
import { canonicalEvidenceJson } from './report-signature.js';
import { readPemKeyFile } from './secure-key-file.js';
import { sanitizeOutput } from './safe-output.js';

const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_MODULE_BYTES = 8 * 1024 * 1024;
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const MAX_MEMORY_PAGES = 256;
const MAX_FINDINGS = 2_000;
const MAX_FILES = 20_000;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_TIMEOUT_MS = 10_000;
const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW;
const signatureSchema = z
  .object({
    algorithm: z.literal('Ed25519'),
    keyId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u),
    value: z.string().regex(/^[A-Za-z0-9+/]{86}==$/u)
  })
  .strict();

const manifestSchema = z
  .object({
    schema: z.literal('toolip.dev/analyzer-plugin/v1'),
    id: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/u),
    apiVersion: z.literal(1),
    module: z.string().min(1).max(256),
    moduleSha256: z.string().regex(/^[a-f0-9]{64}$/u),
    issuedAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
    capabilities: z.array(z.literal('read-snapshot')).min(1).max(1),
    limits: z
      .object({
        timeoutMs: z.number().int().min(1).max(MAX_TIMEOUT_MS),
        memoryPages: z.number().int().min(1).max(MAX_MEMORY_PAGES),
        maxInputBytes: z.number().int().min(1).max(MAX_INPUT_BYTES),
        maxOutputBytes: z.number().int().min(1).max(MAX_OUTPUT_BYTES)
      })
      .strict(),
    signature: signatureSchema
  })
  .strict();

type PluginManifest = z.infer<typeof manifestSchema>;
const verifiedPlugins = new WeakSet<WasmAnalyzerPlugin>();
const verifiedPluginModuleBytes = new WeakMap<WasmAnalyzerPlugin, Uint8Array>();

export async function loadWasmAnalyzerPluginForCli(options: {
  manifestPath?: string;
  publicKeyPath?: string;
  trustedKeyId?: string;
  enabled?: boolean;
}): Promise<WasmAnalyzerPlugin | undefined> {
  const supplied = Boolean(
    options.manifestPath || options.publicKeyPath || options.trustedKeyId
  );
  if (!supplied && options.enabled !== true) return undefined;
  if (options.enabled !== true)
    throw new Error(
      '--enable-executable-plugins is required to run a WASM analyzer plugin.'
    );
  if (!options.manifestPath || !options.publicKeyPath || !options.trustedKeyId)
    throw new Error(
      'A signed plugin manifest, trusted public key and key ID are required.'
    );
  const publicKeyPem = await readPemKeyFile(options.publicKeyPath);
  return loadWasmAnalyzerPlugin(options.manifestPath, {
    publicKeyPem,
    trustedKeyId: options.trustedKeyId
  });
}

export type WasmAnalyzerPlugin = Readonly<{
  id: string;
  apiVersion: 1;
  moduleSha256: string;
  capabilities: readonly 'read-snapshot'[];
  limits: Readonly<PluginManifest['limits']>;
  keyId: string;
}>;

export type PluginInputFile = Readonly<{ path: string; content: string }>;
export type WasmPluginResult = Readonly<{
  coverage: AnalysisCoverage;
  findings: readonly Finding[];
  warnings: readonly string[];
}>;

function readUnsignedLeb(bytes: Uint8Array, state: { offset: number }): number {
  let result = 0;
  let shift = 0;
  for (let count = 0; count < 5; count++) {
    const next = bytes[state.offset++];
    if (next === undefined) throw new Error('WASM section is truncated.');
    result |= (next & 0x7f) << shift;
    if ((next & 0x80) === 0) {
      if (!Number.isSafeInteger(result) || result < 0)
        throw new Error('WASM section length is invalid.');
      return result;
    }
    shift += 7;
  }
  throw new Error('WASM integer is too large.');
}

/** Requires one bounded, non-shared 32-bit memory with an explicit maximum. */
function validateMemorySection(bytes: Uint8Array, maximumPages: number): void {
  if (
    bytes.byteLength < 8 ||
    bytes[0] !== 0 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d ||
    bytes[4] !== 1 ||
    bytes[5] !== 0 ||
    bytes[6] !== 0 ||
    bytes[7] !== 0
  )
    throw new Error('Analyzer plugin is not a supported WebAssembly module.');
  let offset = 8;
  let foundMemory = false;
  while (offset < bytes.byteLength) {
    const sectionId = bytes[offset++];
    if (sectionId === undefined) throw new Error('WASM section is truncated.');
    const sectionCursor = { offset };
    const sectionSize = readUnsignedLeb(bytes, sectionCursor);
    offset = sectionCursor.offset;
    const end = offset + sectionSize;
    if (end > bytes.byteLength) throw new Error('WASM section is truncated.');
    if (sectionId === 5) {
      if (foundMemory)
        throw new Error('Multiple WASM memory sections are denied.');
      foundMemory = true;
      const state = { offset };
      const count = readUnsignedLeb(bytes, state);
      if (count !== 1) throw new Error('Exactly one WASM memory is required.');
      const flags = readUnsignedLeb(bytes, state);
      if (flags !== 1)
        throw new Error(
          'WASM memory must be 32-bit, unshared and explicitly bounded.'
        );
      const minimum = readUnsignedLeb(bytes, state);
      const maximum = readUnsignedLeb(bytes, state);
      if (minimum > maximum || maximum > maximumPages || state.offset !== end)
        throw new Error('WASM memory exceeds the signed plugin limit.');
    }
    offset = end;
  }
  if (!foundMemory)
    throw new Error('Analyzer plugin must define bounded memory.');
}

async function readRegularFile(
  filePath: string,
  maximumBytes: number
): Promise<Uint8Array> {
  const absolute = path.resolve(filePath);
  const before = await lstat(absolute, { bigint: true });
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size > BigInt(maximumBytes)
  )
    throw new Error(
      'Analyzer plugin input must be a bounded regular non-symlink file.'
    );
  const handle = await open(
    absolute,
    constants.O_RDONLY |
      noFollow |
      (process.platform === 'win32' ? 0 : constants.O_NONBLOCK)
  );
  try {
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    )
      throw new Error('Analyzer plugin input changed while opening.');
    const chunks: Buffer[] = [];
    let total = 0;
    while (total <= maximumBytes) {
      const chunk = Buffer.alloc(Math.min(64 * 1024, maximumBytes + 1 - total));
      const read = await handle.read(chunk, 0, chunk.byteLength, null);
      if (read.bytesRead === 0) break;
      total += read.bytesRead;
      if (total > maximumBytes)
        throw new Error('Analyzer plugin input exceeds its byte limit.');
      chunks.push(chunk.subarray(0, read.bytesRead));
    }
    const after = await handle.stat({ bigint: true });
    const named = await lstat(absolute, { bigint: true });
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      named.isSymbolicLink() ||
      named.dev !== opened.dev ||
      named.ino !== opened.ino
    )
      throw new Error('Analyzer plugin input changed while reading.');
    return Buffer.concat(chunks, total);
  } finally {
    await handle.close();
  }
}

function validateManifestPath(value: string): boolean {
  return (
    !path.isAbsolute(value) &&
    !value.includes('\\') &&
    !value.includes('\0') &&
    !value.split('/').includes('..') &&
    value !== '.'
  );
}

const wasmInspectionWorkerSource = `
const { parentPort, workerData } = require('node:worker_threads');
try {
  const module = new WebAssembly.Module(workerData.moduleBytes);
  if (WebAssembly.Module.imports(module).length !== 0) {
    parentPort.postMessage({ ok: false, reason: 'imports' });
  } else {
    const exports = new Map(WebAssembly.Module.exports(module).map((item) => [item.name, item.kind]));
    const valid = exports.get('memory') === 'memory' &&
      exports.get('toolip_alloc') === 'function' &&
      exports.get('toolip_analyze') === 'function' &&
      exports.get('toolip_output_len') === 'function';
    parentPort.postMessage({ ok: valid, reason: valid ? undefined : 'abi' });
  }
} catch {
  parentPort.postMessage({ ok: false, reason: 'compile' });
}
`;

async function inspectWasmModuleInWorker(
  moduleBytes: Uint8Array
): Promise<'ok' | 'imports' | 'abi' | 'compile' | 'timeout'> {
  let worker: Worker;
  try {
    worker = new Worker(wasmInspectionWorkerSource, {
      eval: true,
      workerData: { moduleBytes },
      resourceLimits: {
        maxOldGenerationSizeMb: 32,
        maxYoungGenerationSizeMb: 8,
        stackSizeMb: 2
      }
    });
  } catch {
    return 'compile';
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (
      result: 'ok' | 'imports' | 'abi' | 'compile' | 'timeout'
    ): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      void worker.terminate().then(
        () => resolve(result),
        () => resolve(result)
      );
    };
    const timeout = setTimeout(() => finish('timeout'), MAX_TIMEOUT_MS);
    worker.once('message', (message: unknown) => {
      if (
        message &&
        typeof message === 'object' &&
        'ok' in message &&
        message.ok === true
      )
        finish('ok');
      else if (
        message &&
        typeof message === 'object' &&
        'reason' in message &&
        (message.reason === 'imports' ||
          message.reason === 'abi' ||
          message.reason === 'compile')
      )
        finish(message.reason);
      else finish('compile');
    });
    worker.once('error', () => finish('compile'));
    worker.once('exit', () => {
      if (!settled) finish('compile');
    });
  });
}

/** Loads a signed plugin whose WebAssembly module has no ambient imports. */
export async function loadWasmAnalyzerPlugin(
  manifestPath: string,
  options: {
    publicKeyPem: string;
    trustedKeyId: string;
    now?: number;
  }
): Promise<WasmAnalyzerPlugin> {
  const manifestBytes = await readRegularFile(manifestPath, MAX_MANIFEST_BYTES);
  let raw: unknown;
  try {
    raw = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes)
    );
  } catch {
    throw new Error('Analyzer plugin manifest is invalid JSON.');
  }
  const parsed = manifestSchema.safeParse(raw);
  if (!parsed.success) throw new Error('Analyzer plugin manifest is invalid.');
  const manifest = parsed.data;
  if (!validateManifestPath(manifest.module))
    throw new Error(
      'Analyzer plugin module path must stay beside its manifest.'
    );
  if (manifest.signature.keyId !== options.trustedKeyId)
    throw new Error('Analyzer plugin signing key is not trusted.');
  const now = options.now ?? Date.now();
  const issuedAt = Date.parse(manifest.issuedAt);
  const expiresAt = Date.parse(manifest.expiresAt);
  if (
    issuedAt > now + 5 * 60 * 1000 ||
    expiresAt <= now ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > 180 * 24 * 60 * 60 * 1000
  )
    throw new Error(
      'Analyzer plugin signature is expired or has invalid dates.'
    );
  const { signature, ...payload } = manifest;
  const canonical = canonicalEvidenceJson(payload);
  let verified = false;
  try {
    verified = cryptoVerify(
      null,
      Buffer.from(canonical),
      options.publicKeyPem,
      Buffer.from(signature.value, 'base64')
    );
  } catch {
    verified = false;
  }
  if (!verified)
    throw new Error('Analyzer plugin signature verification failed.');

  const manifestRoot = await realpath(path.dirname(path.resolve(manifestPath)));
  const modulePath = path.resolve(manifestRoot, manifest.module);
  const moduleRoot = await realpath(path.dirname(modulePath));
  if (moduleRoot !== manifestRoot)
    throw new Error(
      'Analyzer plugin module must remain in its manifest directory.'
    );
  const moduleBytes = await readRegularFile(modulePath, MAX_MODULE_BYTES);
  const moduleSha256 = createHash('sha256').update(moduleBytes).digest('hex');
  if (moduleSha256 !== manifest.moduleSha256)
    throw new Error(
      'Analyzer plugin module digest does not match its signature.'
    );
  validateMemorySection(moduleBytes, manifest.limits.memoryPages);
  const inspection = await inspectWasmModuleInWorker(moduleBytes);
  if (inspection === 'imports')
    throw new Error('Analyzer plugin WASM imports are denied.');
  if (inspection === 'abi')
    throw new Error(
      'Analyzer plugin does not implement the Toolip WASM ABI v1.'
    );
  if (inspection === 'timeout')
    throw new Error('Analyzer plugin WASM validation timed out.');
  if (inspection !== 'ok')
    throw new Error('Analyzer plugin WASM module could not be validated.');
  const plugin: WasmAnalyzerPlugin = Object.freeze({
    id: manifest.id,
    apiVersion: 1,
    moduleSha256,
    capabilities: Object.freeze([...manifest.capabilities]),
    limits: Object.freeze({ ...manifest.limits }),
    keyId: signature.keyId
  });
  // Typed arrays cannot be frozen safely in JavaScript. Keep the only copy
  // used for execution in module-private state so callers cannot replace the
  // signed code after verification while retaining its original digest.
  verifiedPluginModuleBytes.set(plugin, new Uint8Array(moduleBytes));
  verifiedPlugins.add(plugin);
  return plugin;
}

function safePluginPath(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 512 &&
    !value.includes('\\') &&
    !value.includes('\0') &&
    !path.posix.isAbsolute(value) &&
    !value.split('/').includes('..')
  );
}

const pluginFindingSchema = z
  .object({
    ruleId: z.string().regex(/^[A-Z0-9][A-Z0-9._-]{1,127}$/u),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    confidence: z.enum(['high', 'medium', 'low']),
    file: z.string().min(1).max(512),
    line: z.number().int().min(1).max(10_000_000),
    column: z.number().int().min(1).max(10_000)
  })
  .strict();

const pluginOutputSchema = z
  .object({
    schemaVersion: z.literal(1),
    findings: z.array(pluginFindingSchema).max(MAX_FINDINGS)
  })
  .strict();

const wasmWorkerSource = `
const { parentPort, workerData } = require('node:worker_threads');
try {
  const module = new WebAssembly.Module(workerData.moduleBytes);
  const instance = new WebAssembly.Instance(module, {});
  const { memory, toolip_alloc, toolip_analyze, toolip_output_len } = instance.exports;
  if (!(memory instanceof WebAssembly.Memory)) throw new Error('abi');
  const input = new TextEncoder().encode(workerData.input);
  const inputPointer = toolip_alloc(input.byteLength);
  if (!Number.isInteger(inputPointer) || inputPointer < 0 || inputPointer + input.byteLength > memory.buffer.byteLength) throw new Error('input-bounds');
  new Uint8Array(memory.buffer, inputPointer, input.byteLength).set(input);
  const outputPointer = toolip_analyze(inputPointer, input.byteLength);
  const outputLength = toolip_output_len();
  if (!Number.isInteger(outputPointer) || outputPointer < 0 || !Number.isInteger(outputLength) || outputLength < 1 || outputLength > workerData.maxOutputBytes || outputPointer + outputLength > memory.buffer.byteLength) throw new Error('output-bounds');
  const output = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(memory.buffer, outputPointer, outputLength));
  parentPort.postMessage({ ok: true, output });
} catch {
  parentPort.postMessage({ ok: false });
}
`;

function pluginFailure(fileCount: number, warning: string): WasmPluginResult {
  return {
    coverage: coverageOf({
      eligible: fileCount,
      scanned: 0,
      skipped: fileCount,
      failed: 1
    }),
    findings: [],
    warnings: [warning]
  };
}

/** Runs one signed WASM module in a terminable worker with no host imports. */
export async function runWasmAnalyzerPlugin(
  plugin: WasmAnalyzerPlugin,
  files: readonly PluginInputFile[],
  signal?: AbortSignal
): Promise<WasmPluginResult> {
  if (!verifiedPlugins.has(plugin))
    throw new Error('Analyzer plugin was not loaded from a trusted signature.');
  const moduleBytes = verifiedPluginModuleBytes.get(plugin);
  if (!moduleBytes)
    throw new Error('Verified analyzer plugin module bytes are unavailable.');
  if (signal?.aborted) return pluginFailure(files.length, 'plugin-cancelled');
  if (files.length > MAX_FILES)
    return pluginFailure(files.length, 'plugin-file-budget-exceeded');
  const paths = new Set<string>();
  let fileBytes = 0;
  for (const file of files) {
    const bytes = Buffer.byteLength(file.content, 'utf8');
    if (
      !safePluginPath(file.path) ||
      paths.has(file.path) ||
      bytes > MAX_FILE_BYTES
    )
      return pluginFailure(files.length, 'plugin-input-invalid-or-over-budget');
    paths.add(file.path);
    fileBytes += bytes;
    if (fileBytes > plugin.limits.maxInputBytes)
      return pluginFailure(files.length, 'plugin-input-budget-exceeded');
  }
  const input = JSON.stringify({
    schemaVersion: 1,
    files: files.map(({ path: filePath, content }) => ({
      path: filePath,
      content
    }))
  });
  if (Buffer.byteLength(input, 'utf8') > plugin.limits.maxInputBytes)
    return pluginFailure(files.length, 'plugin-input-budget-exceeded');
  if (signal?.aborted) return pluginFailure(files.length, 'plugin-cancelled');

  let worker: Worker;
  try {
    worker = new Worker(wasmWorkerSource, {
      eval: true,
      workerData: {
        moduleBytes,
        input,
        maxOutputBytes: plugin.limits.maxOutputBytes
      },
      resourceLimits: {
        maxOldGenerationSizeMb: 32,
        maxYoungGenerationSizeMb: 8,
        stackSizeMb: 2
      }
    });
  } catch {
    return pluginFailure(files.length, 'plugin-worker-unavailable');
  }

  const workerResult = await new Promise<
    | { kind: 'result'; value: unknown }
    | { kind: 'timeout' | 'cancelled' | 'failed' }
  >((resolve) => {
    let settled = false;
    const finish = (
      result:
        | { kind: 'result'; value: unknown }
        | { kind: 'timeout' | 'cancelled' | 'failed' },
      terminateWorker = false
    ) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
      if (terminateWorker) {
        void worker.terminate().then(
          () => resolve(result),
          () => resolve(result)
        );
      } else {
        resolve(result);
      }
    };
    const timeout = setTimeout(() => {
      finish({ kind: 'timeout' }, true);
    }, plugin.limits.timeoutMs);
    const abort = () => {
      finish({ kind: 'cancelled' }, true);
    };
    signal?.addEventListener('abort', abort, { once: true });
    worker.once('message', (message: unknown) => {
      if (
        message &&
        typeof message === 'object' &&
        'ok' in message &&
        message.ok === true &&
        'output' in message &&
        typeof message.output === 'string'
      )
        finish({ kind: 'result', value: message.output }, true);
      else finish({ kind: 'failed' }, true);
    });
    worker.once('error', () => finish({ kind: 'failed' }, true));
    worker.once('exit', (code) => {
      if (code !== 0) finish({ kind: 'failed' });
    });
    if (signal?.aborted) abort();
  });
  if (workerResult.kind !== 'result')
    return pluginFailure(
      files.length,
      workerResult.kind === 'timeout'
        ? 'plugin-timeout'
        : workerResult.kind === 'cancelled'
          ? 'plugin-cancelled'
          : 'plugin-execution-failed'
    );

  const raw = workerResult.value;
  if (
    typeof raw !== 'string' ||
    Buffer.byteLength(raw, 'utf8') > plugin.limits.maxOutputBytes
  )
    return pluginFailure(files.length, 'plugin-output-budget-exceeded');
  let output: unknown;
  try {
    output = JSON.parse(raw);
  } catch {
    return pluginFailure(files.length, 'plugin-output-invalid');
  }
  const parsed = pluginOutputSchema.safeParse(output);
  if (!parsed.success)
    return pluginFailure(files.length, 'plugin-output-invalid');
  const inputPaths = new Set(files.map((file) => file.path));
  if (
    parsed.data.findings.some(
      (finding) =>
        !inputPaths.has(finding.file) ||
        !new RegExp(`^TLP-PLUGIN-${plugin.id.toUpperCase()}-\\d{3}$`, 'u').test(
          finding.ruleId
        )
    )
  )
    return pluginFailure(files.length, 'plugin-output-reference-invalid');

  const findings: Finding[] = parsed.data.findings.map((rawFinding) => {
    const clean = sanitizeOutput(rawFinding);
    const key = `${plugin.id}\0${clean.ruleId}\0${clean.file}\0${clean.line}\0${clean.column}`;
    const fingerprint = createHash('sha256').update(key).digest('hex');
    return {
      id: `TLP-PLUGIN-${plugin.id.toUpperCase()}-${fingerprint.slice(0, 24)}`,
      ruleId: clean.ruleId,
      title: clean.ruleId,
      category: 'third-party-analyzer',
      severity: clean.severity,
      confidence: clean.confidence,
      message:
        'A signed analyzer reported a finding at this source location. Review the rule definition and verify the result manually.',
      source: `signed-wasm-plugin:${plugin.id}`,
      location: {
        file: clean.file,
        line: clean.line,
        column: clean.column
      },
      evidence: [
        {
          summary: 'Finding reported by a signed, capability-limited analyzer.',
          fingerprint
        }
      ],
      remediation: {
        summary:
          'Review the signed analyzer rule and affected source before applying a change.'
      },
      metadata: {
        pluginId: plugin.id,
        pluginApiVersion: plugin.apiVersion,
        pluginSha256: plugin.moduleSha256,
        pluginKeyId: plugin.keyId
      }
    };
  });
  return {
    coverage: coverageOf({
      eligible: files.length,
      scanned: files.length,
      skipped: 0,
      failed: 0
    }),
    findings,
    warnings: []
  };
}
