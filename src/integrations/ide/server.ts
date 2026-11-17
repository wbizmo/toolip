import { createInterface } from 'node:readline';
import { analyzeAstSource } from '../../analyzers/ast/source-analysis.js';
import { redactSensitiveText } from '../../core/safe-output.js';
import { serializeJsonOutputWithinBudget } from '../../core/report-writer.js';

const maximumRequestBytes = 768 * 1024;
const maximumDocumentBytes = 512 * 1024;
const maximumTotalDocumentBytes = 4 * 1024 * 1024;
const maximumOpenDocuments = 32;
const maximumResponseBytes = 512 * 1024;

type OpenDocument = {
  version: number;
  text: string;
  bytes: number;
};

export type IdeRequest = Readonly<{
  jsonrpc: '2.0';
  id?: string | number;
  method: string;
  params?: unknown;
}>;

export type IdeResponse = Readonly<{
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: Readonly<{ code: number; message: string }>;
}>;

const supported = /\.(?:[cm]?[jt]s|[jt]sx)$/iu;

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function permittedPath(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 1024 &&
    !value.includes('\\') && !value.includes('\0') &&
    !value.startsWith('/') && !value.endsWith('/') &&
    !value.split('/').some((part) => part === '..' || part === '.' || !part) &&
    supported.test(value);
}

export class IdeAnalyzerSession {
  private documents = new Map<string, OpenDocument>();
  private retainedBytes = 0;

  async handle(request: IdeRequest): Promise<IdeResponse> {
    const id = request.id ?? null;
    const reply = (result: unknown): IdeResponse => ({ jsonrpc: '2.0', id, result });
    const error = (code: number, message: string): IdeResponse => ({
      jsonrpc: '2.0', id, error: { code, message }
    });
    if (request.jsonrpc !== '2.0' || typeof request.method !== 'string')
      return error(-32600, 'Invalid JSON-RPC request.');
    if (request.method === 'initialize') return reply({
      protocol: 'toolip.dev/ide-jsonrpc/v1',
      server: 'toolip',
      network: 'disabled',
      workspaceExecution: 'disabled',
      completeProjectAnalysis: false,
      maximumDocumentBytes,
      capabilities: ['textDocument/didOpen', 'textDocument/didChange',
        'textDocument/didClose', 'textDocument/diagnostic']
    });
    const params = asRecord(request.params);
    const file = params?.path;
    if (!permittedPath(file))
      return error(-32602, 'Document path must be a bounded relative source path.');
    if (request.method === 'textDocument/didClose') {
      const previous = this.documents.get(file);
      if (previous) {
        this.retainedBytes -= previous.bytes;
        this.documents.delete(file);
      }
      return reply({ closed: true });
    }
    if (request.method === 'textDocument/didOpen' ||
        request.method === 'textDocument/didChange') {
      const text = params?.text;
      const version = params?.version;
      if (typeof text !== 'string' || typeof version !== 'number' ||
          !Number.isSafeInteger(version) || version < 0)
        return error(-32602, 'Document content and version are invalid.');
      const bytes = Buffer.byteLength(text, 'utf8');
      const previous = this.documents.get(file);
      if (previous && version <= previous.version)
        return error(-32001, 'Stale document version; no diagnostics were updated.');
      if (bytes > maximumDocumentBytes)
        return error(-32002, 'Document is over the bounded analysis size.');
      if (!previous && this.documents.size >= maximumOpenDocuments)
        return error(-32002, 'Too many open documents.');
      if (this.retainedBytes - (previous?.bytes ?? 0) + bytes > maximumTotalDocumentBytes)
        return error(-32002, 'Document memory budget exceeded.');
      this.documents.set(file, { version, text, bytes });
      this.retainedBytes += bytes - (previous?.bytes ?? 0);
      return reply({ path: file, version, accepted: true });
    }
    if (request.method === 'textDocument/diagnostic') {
      const current = this.documents.get(file);
      if (!current) return error(-32003, 'Document was not opened.');
      const findings = analyzeAstSource(file, current.text);
      return reply({
        path: file,
        version: current.version,
        state: 'partial',
        reason: 'Unsaved-buffer AST analysis excludes cross-file project context.',
        findings: findings.slice(0, 500).map((finding) => ({
          id: redactSensitiveText(finding.id).slice(0, 128),
          ruleId: finding.ruleId,
          severity: finding.severity,
          confidence: finding.confidence,
          message: redactSensitiveText(finding.message).slice(0, 1024),
          line: finding.location?.line,
          column: finding.location?.column
        })),
        findingsTruncated: findings.length > 500
      });
    }
    return error(-32601, 'Unknown IDE method.');
  }

  get openDocumentCount(): number { return this.documents.size; }
  get retainedDocumentBytes(): number { return this.retainedBytes; }
}

/** Stdio is a capability-limited protocol, never a shell or arbitrary code executor. */
export async function serveIdeJsonRpc(
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stdout
): Promise<void> {
  const session = new IdeAnalyzerSession();
  const lines = createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    let response: IdeResponse;
    if (Buffer.byteLength(line, 'utf8') > maximumRequestBytes) {
      response = { jsonrpc: '2.0', id: null, error: {
        code: -32600, message: 'IDE request exceeds maximum size.'
      } };
    } else {
      try {
        const parsed = JSON.parse(line) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
          throw new TypeError('Invalid request.');
        response = await session.handle(parsed as IdeRequest);
      } catch {
        response = { jsonrpc: '2.0', id: null, error: {
          code: -32700, message: 'IDE request is malformed.'
        } };
      }
    }
    try {
      output.write(serializeJsonOutputWithinBudget(response, maximumResponseBytes) + '\n');
    } catch {
      output.write('{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Response budget exceeded."}}\n');
    }
  }
}
