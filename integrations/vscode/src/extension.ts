import * as vscode from 'vscode';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import path from 'node:path';
import { mkdirSync } from 'node:fs';
import { trustedIdeExecutable } from './trusted-executable.js';

type Pending = { uri: vscode.Uri; version: number };
type RpcResponse = {
  id?: number | null;
  result?: {
    version?: number;
    state?: string;
    findings?: Array<{
      id?: string;
      severity?: string;
      message?: string;
      line?: number;
      column?: number;
    }>;
  };
  error?: { code?: number; message?: string };
};

const maxDocumentBytes = 512 * 1024;
const maxResponseBytes = 512 * 1024;
const languages = new Set([
  'javascript', 'typescript', 'javascriptreact', 'typescriptreact'
]);

let processInstance: ChildProcessWithoutNullStreams | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection('toolip');
  context.subscriptions.push(diagnostics);
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 0 || !vscode.workspace.isTrusted) return;

  const config = vscode.workspace.getConfiguration('toolip');
  // Workspaces can supply .vscode/settings.json; they MUST NOT control
  // whether an analyzer launches or which local executable it launches.
  // Read only explicit USER/global settings, never effective .get values.
  if (config.inspect<boolean>('enabled')?.globalValue !== true) return;
  const configured = config.inspect<string>('executablePath')?.globalValue;
  const executable = trustedIdeExecutable(
    configured,
    folders.map((folder) => folder.uri.fsPath)
  );
  if (!executable) return;
  // The source project is always treated as inert input, never the working
  // directory for a spawned security process.
  const safeWorkingDirectory = context.globalStorageUri.fsPath;
  try {
    mkdirSync(safeWorkingDirectory, { recursive: true, mode: 0o700 });
  } catch {
    return;
  }
  const child = spawn(executable, ['ide', 'serve'], {
    cwd: safeWorkingDirectory,
    shell: false,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      USERPROFILE: process.env.USERPROFILE,
      SYSTEMROOT: process.env.SYSTEMROOT,
      TMPDIR: process.env.TMPDIR,
      TEMP: process.env.TEMP
    }
  });
  processInstance = child;

  let nextId = 1;
  let received = '';
  const pending = new Map<number, Pending>();
  const supported = (document: vscode.TextDocument): string | undefined => {
    if (!languages.has(document.languageId)) return undefined;
    if (document.uri.scheme !== 'file') return undefined;
    const folder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!folder) return undefined;
    const index = folders.findIndex((item) =>
      item.uri.toString() === folder.uri.toString()
    );
    if (index < 0) return undefined;
    const relative = path.relative(folder.uri.fsPath, document.uri.fsPath);
    if (!relative || path.isAbsolute(relative) || relative === '..' ||
        relative.startsWith(`..${path.sep}`)) return undefined;
    const normalized = relative.replaceAll(path.sep, '/');
    // Keep documents from independent workspace roots isolated in the one
    // local analyzer session even when their relative paths are identical.
    return folders.length === 1
      ? normalized
      : `workspace-${index}/${normalized}`;
  };

  const send = (
    method: string,
    document: vscode.TextDocument,
    params: Record<string, unknown>,
    expectDiagnostics: boolean
  ): void => {
    const relative = supported(document);
    if (!relative || child.killed || !child.stdin.writable) return;
    const id = nextId++;
    if (expectDiagnostics) {
      if (pending.size >= 128) {
        diagnostics.set(document.uri, [new vscode.Diagnostic(
          new vscode.Range(0, 0, 0, 1),
          'Toolip local analysis backlog exceeded; security coverage is incomplete.',
          vscode.DiagnosticSeverity.Warning
        )]);
        return;
      }
      pending.set(id, { uri: document.uri, version: document.version });
    }
    const payload = JSON.stringify({
      jsonrpc: '2.0', id, method, params: { path: relative, ...params }
    });
    if (Buffer.byteLength(payload, 'utf8') > maxDocumentBytes + 16 * 1024) {
      pending.delete(id);
      return;
    }
    child.stdin.write(payload + '\n');
  };

  const submit = (document: vscode.TextDocument, opened: boolean): void => {
    const relative = supported(document);
    if (!relative) return;
    const text = document.getText();
    if (Buffer.byteLength(text, 'utf8') > maxDocumentBytes) {
      diagnostics.set(document.uri, [new vscode.Diagnostic(
        new vscode.Range(0, 0, 0, 1),
        'Toolip: document exceeds the local analysis size limit; no security all-clear.',
        vscode.DiagnosticSeverity.Warning
      )]);
      return;
    }
    send(opened ? 'textDocument/didOpen' : 'textDocument/didChange',
      document, { version: document.version, text }, false);
    send('textDocument/diagnostic', document, {}, true);
  };

  const onLine = (line: string): void => {
    let message: RpcResponse;
    try {
      message = JSON.parse(line) as RpcResponse;
    } catch {
      return;
    }
    if (typeof message.id !== 'number') return;
    const inflight = pending.get(message.id);
    if (!inflight) return;
    pending.delete(message.id);
    const document = vscode.workspace.textDocuments.find(
      (candidate) => candidate.uri.toString() === inflight.uri.toString()
    );
    if (!document || document.version !== inflight.version) return;
    if (message.error || !message.result || message.result.version !== inflight.version) {
      diagnostics.set(inflight.uri, [new vscode.Diagnostic(
        new vscode.Range(0, 0, 0, 1),
        'Toolip analysis incomplete; no security all-clear.',
        vscode.DiagnosticSeverity.Warning
      )]);
      return;
    }
    const items = (message.result.findings ?? []).slice(0, 500).map((finding) => {
      const lineNumber = Math.max(0, Math.min(document.lineCount - 1,
        (finding.line ?? 1) - 1));
      const column = Math.max(0, (finding.column ?? 1) - 1);
      const range = new vscode.Range(
        lineNumber, column, lineNumber, column + 1
      );
      const severity = finding.severity === 'critical' || finding.severity === 'high'
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;
      const diagnostic = new vscode.Diagnostic(
        range,
        (finding.message ?? 'Toolip security finding').slice(0, 1024),
        severity
      );
      diagnostic.source = 'Toolip (local, partial coverage)';
      diagnostic.code = finding.id;
      return diagnostic;
    });
    diagnostics.set(inflight.uri, items);
  };

  child.stdout.on('data', (data: Buffer) => {
    received += data.toString('utf8');
    if (Buffer.byteLength(received, 'utf8') > maxResponseBytes * 2) {
      received = '';
      child.kill();
      return;
    }
    let boundary = received.indexOf('\n');
    while (boundary >= 0) {
      const line = received.slice(0, boundary);
      received = received.slice(boundary + 1);
      if (Buffer.byteLength(line, 'utf8') <= maxResponseBytes) onLine(line);
      boundary = received.indexOf('\n');
    }
  });
  child.stderr.on('data', () => {
    // Do not display raw scanner stderr which might contain sensitive paths.
  });
  child.on('error', () => {
    // Spawn errors are otherwise unhandled EventEmitter errors. Never render
    // raw filesystem paths or tool output as an IDE diagnostic.
    pending.clear();
    diagnostics.clear();
  });
  child.on('close', () => {
    pending.clear();
    // Results from an exited process are stale, not ongoing proof of safety.
    diagnostics.clear();
    if (processInstance === child) processInstance = undefined;
  });

  for (const document of vscode.workspace.textDocuments) submit(document, true);
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document) => submit(document, true)),
    vscode.workspace.onDidChangeTextDocument(({ document }) => submit(document, false)),
    vscode.workspace.onDidCloseTextDocument((document) => {
      send('textDocument/didClose', document, {}, false);
      diagnostics.delete(document.uri);
    }),
    { dispose: () => child.kill() }
  );
}

export function deactivate(): void {
  processInstance?.kill();
  processInstance = undefined;
}
