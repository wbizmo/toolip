import { spawn } from 'node:child_process';
import {
  access,
  constants,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { DependencyFileSource } from './inventory.js';

const maxMetadataFiles = 5_000;
const maxMetadataBytes = 32 * 1024 * 1024;
const maxCommandOutputBytes = 16 * 1024 * 1024;
const maxCommandMs = 90_000;

export type GoCommandRunner = (input: {
  executable: string;
  cwd: string;
  args: readonly string[];
  env: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}) => Promise<string>;

export type GoModuleGraphCapture = {
  modulesJson: string;
  graphText: string;
  /** Fresh sums emitted by Go after sum.golang.org verification. */
  goSums: ReadonlyMap<string, string>;
  /** Sums captured from the caller's immutable project snapshot. */
  sourceGoSums: ReadonlyMap<string, string>;
};

function withinSnapshotPath(relative: string): boolean {
  const normalized = relative.replaceAll('\\', '/');
  return (
    normalized.length > 0 &&
    normalized === relative &&
    !normalized.startsWith('/') &&
    !normalized.split('/').some((part) => part === '..' || part === '.') &&
    !normalized.includes('\0')
  );
}

function parseGoSums(text: string): Map<string, string> {
  const sums = new Map<string, string>();
  for (const line of text.split(/\r?\n/u)) {
    const [module, version, sum, extra] = line.trim().split(/\s+/u);
    if (!module || !version || !sum || extra !== undefined) continue;
    const encoded = /^h1:([A-Za-z0-9+/]+={0,2})$/u.exec(sum)?.[1];
    if (!encoded || Buffer.from(encoded, 'base64').length !== 32) continue;
    const key = `${module}@${version}`;
    const existing = sums.get(key);
    if (existing && existing !== sum) {
      sums.delete(key);
      sums.set(key, '');
    } else if (existing === undefined) {
      sums.set(key, sum);
    }
  }
  return sums;
}

async function runGoCommand(input: {
  executable: string;
  cwd: string;
  args: readonly string[];
  env: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}): Promise<string> {
  if (input.signal?.aborted) throw new Error('Go graph resolution cancelled.');
  return new Promise((resolve, reject) => {
    const child = spawn(input.executable, [...input.args], {
      cwd: input.cwd,
      env: input.env,
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true
    });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    let stopError: Error | undefined;
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    let forceKillTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error?: Error, result?: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (killTimer) clearTimeout(killTimer);
      if (forceKillTimer) clearTimeout(forceKillTimer);
      input.signal?.removeEventListener('abort', abort);
      if (error) reject(error);
      else resolve(result ?? '');
    };
    const stop = (error: Error): void => {
      if (settled || stopError) return;
      stopError = error;
      child.kill();
      forceKillTimer = setTimeout(() => child.kill('SIGKILL'), 1_000);
    };
    const abort = (): void => stop(new Error('Go graph resolution cancelled.'));
    const timeout = setTimeout(
      () => stop(new Error('Go graph resolution timed out.')),
      maxCommandMs
    );
    input.signal?.addEventListener('abort', abort, { once: true });
    child.stdout.on('data', (chunk: Buffer) => {
      if (stopError) return;
      bytes += chunk.length;
      if (bytes > maxCommandOutputBytes) {
        stop(new Error('Go graph output exceeded its configured budget.'));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    child.once('error', () =>
      finish(new Error('The Go tool could not be started.'))
    );
    child.once('close', (code, signal) => {
      if (settled) return;
      if (stopError) {
        finish(stopError);
        return;
      }
      if (code !== 0) {
        finish(
          new Error(
            signal
              ? 'The Go tool was interrupted.'
              : 'The Go tool could not resolve a complete module graph.'
          )
        );
        return;
      }
      finish(undefined, Buffer.concat(chunks, bytes).toString('utf8'));
    });
    if (input.signal?.aborted) abort();
  });
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === '' ||
    (!path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`))
  );
}

function hasExecutableImageHeader(header: Buffer): boolean {
  if (process.platform === 'win32') return header.subarray(0, 2).toString() === 'MZ';
  if (header.length < 4) return false;
  const signatures = [
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]), // ELF
    Buffer.from([0xfe, 0xed, 0xfa, 0xce]), // Mach-O, 32-bit big endian
    Buffer.from([0xce, 0xfa, 0xed, 0xfe]), // Mach-O, 32-bit little endian
    Buffer.from([0xfe, 0xed, 0xfa, 0xcf]), // Mach-O, 64-bit big endian
    Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), // Mach-O, 64-bit little endian
    Buffer.from([0xca, 0xfe, 0xba, 0xbe]), // Universal Mach-O
    Buffer.from([0xca, 0xfe, 0xba, 0xbf]) // Universal 64-bit Mach-O
  ];
  return signatures.some((signature) => header.subarray(0, 4).equals(signature));
}

async function findGoExecutable(
  projectRoot: string,
  temporaryRoot: string
): Promise<string> {
  const executableName = process.platform === 'win32' ? 'go.exe' : 'go';
  for (const entry of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!entry) continue;
    const searchDirectory = path.isAbsolute(entry)
      ? entry
      : path.resolve(temporaryRoot, entry);
    const candidate = path.join(searchDirectory, executableName);
    const resolved = await realpath(candidate).catch(() => undefined);
    if (
      !resolved ||
      isWithin(projectRoot, resolved) ||
      isWithin(temporaryRoot, resolved)
    )
      continue;
    const file = await lstat(resolved).catch(() => undefined);
    if (!file?.isFile()) continue;
    if (process.platform !== 'win32') {
      const executable = await access(resolved, constants.X_OK).then(
        () => true,
        () => false
      );
      if (!executable) continue;
    }
    const handle = await open(
      resolved,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
    ).catch(() => undefined);
    if (!handle) continue;
    try {
      const header = Buffer.alloc(4);
      const { bytesRead } = await handle.read(header, 0, header.length, 0);
      if (hasExecutableImageHeader(header.subarray(0, bytesRead)))
        return resolved;
    } finally {
      await handle.close();
    }
  }
  throw new Error('No external Go executable was found on PATH.');
}

/**
 * Runs only after explicit caller consent. The tool sees a private copy of
 * captured module metadata, uses isolated Go caches and the official Go proxy
 * and checksum database, and never imports or builds repository source.
 */
export async function captureGoMvsGraph(
  root: string,
  fileSource: DependencyFileSource | undefined,
  options: {
    signal?: AbortSignal;
    runner?: GoCommandRunner;
  } = {}
): Promise<GoModuleGraphCapture> {
  if (!fileSource)
    throw new Error('Go tool execution requires an immutable project snapshot.');
  if (options.signal?.aborted)
    throw new Error('Go graph resolution cancelled.');

  const metadataFiles = fileSource.files
    .filter((file) =>
      /(?:^|\/)(?:go\.(?:mod|sum)|go\.work(?:\.sum)?)$/u.test(file)
    )
    .sort();
  if (metadataFiles.length === 0 || metadataFiles.length > maxMetadataFiles)
    throw new Error('Go module metadata is missing or exceeds its file budget.');

  const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), 'toolip-go-mvs-'));
  try {
    let bytes = 0;
    const sums = new Map<string, string>();
    const sourceSums = new Map<string, string>();
    const mergeSums = (
      records: ReadonlyMap<string, string>,
      target: Map<string, string> = sums
    ): void => {
      for (const [key, value] of records) {
        const prior = target.get(key);
        if (prior === undefined) target.set(key, value);
        else if (prior !== value) target.set(key, '');
      }
    };
    for (const relative of metadataFiles) {
      if (!withinSnapshotPath(relative))
        throw new Error('Go module metadata contains an unsafe path.');
      const content = fileSource.readText(relative);
      if (content === undefined)
        throw new Error('Go module metadata is absent from the immutable snapshot.');
      const size = Buffer.byteLength(content, 'utf8');
      bytes += size;
      if (bytes > maxMetadataBytes)
        throw new Error('Go module metadata exceeds its byte budget.');
      if (relative.endsWith('.sum')) {
        mergeSums(parseGoSums(content), sourceSums);
        continue;
      }
      const target = path.join(temporaryRoot, ...relative.split('/'));
      await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, content, { flag: 'wx', mode: 0o600 });
    }

    const cacheRoot = path.join(temporaryRoot, '.cache');
    const workspaceMode = metadataFiles.some(
      (file) => path.basename(file) === 'go.work'
    );
    const run = options.runner ?? runGoCommand;
    const executable = options.runner
      ? 'injected-go-command-runner'
      : await findGoExecutable(root, temporaryRoot);
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      ...(process.env.WINDIR ? { WINDIR: process.env.WINDIR } : {}),
      ...(process.env.HTTPS_PROXY ? { HTTPS_PROXY: process.env.HTTPS_PROXY } : {}),
      ...(process.env.https_proxy ? { https_proxy: process.env.https_proxy } : {}),
      ...(process.env.HTTP_PROXY ? { HTTP_PROXY: process.env.HTTP_PROXY } : {}),
      ...(process.env.http_proxy ? { http_proxy: process.env.http_proxy } : {}),
      ...(process.env.NO_PROXY ? { NO_PROXY: process.env.NO_PROXY } : {}),
      ...(process.env.no_proxy ? { no_proxy: process.env.no_proxy } : {}),
      HOME: temporaryRoot,
      USERPROFILE: temporaryRoot,
      GOPATH: path.join(cacheRoot, 'gopath'),
      GOMODCACHE: path.join(cacheRoot, 'gomodcache'),
      GOCACHE: path.join(cacheRoot, 'gocache'),
      GOENV: 'off',
      GOTOOLCHAIN: 'local',
      // A standalone module may omit go.sum in the immutable snapshot, so let
      // Go populate fresh sums in its private copy. Workspace mode rejects
      // -mod=mod and maintains workspace checksums in go.work.sum instead.
      ...(workspaceMode ? {} : { GOFLAGS: '-mod=mod' }),
      GOMAXPROCS: '2',
      GOMEMLIMIT: '768MiB',
      GOPROXY: 'https://proxy.golang.org',
      GOSUMDB: 'sum.golang.org'
    };
    const versionOutput = await run({
      executable,
      cwd: temporaryRoot,
      args: ['version'],
      env,
      signal: options.signal
    });
    if (!/^go version go\d+\.\d+(?:\.\d+)?(?:\s|$)/u.test(versionOutput.trim()))
      throw new Error('The executable on PATH is not the Go module tool.');
    const modulesJson = await run({
      executable,
      cwd: temporaryRoot,
      args: ['list', '-m', '-json', 'all'],
      env,
      signal: options.signal
    });
    const graphText = await run({
      executable,
      cwd: temporaryRoot,
      args: ['mod', 'graph'],
      env,
      signal: options.signal
    });
    // Go may add authenticated go.mod sums to the isolated copy. Return only
    // syntactically valid entries; callers still compare each result exactly.
    const sumFiles = new Set(
      metadataFiles
        .filter((file) => path.basename(file) === 'go.sum')
        .map((file) => path.join(temporaryRoot, ...file.split('/')))
    );
    sumFiles.add(path.join(temporaryRoot, 'go.sum'));
    sumFiles.add(path.join(temporaryRoot, 'go.work.sum'));
    for (const target of sumFiles) {
      const content = await readFile(target, 'utf8').catch(() => '');
      mergeSums(parseGoSums(content), sums);
    }
    void root;
    return {
      modulesJson,
      graphText,
      goSums: sums,
      sourceGoSums: sourceSums
    };
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

export function parseGoModuleJsonStream(text: string): Record<string, unknown>[] {
  if (Buffer.byteLength(text, 'utf8') > maxCommandOutputBytes)
    throw new Error('Go module output exceeds its configured byte budget.');
  const records: Record<string, unknown>[] = [];
  let cursor = 0;
  while (cursor < text.length) {
    while (/\s/u.test(text[cursor] ?? '')) cursor++;
    if (cursor === text.length) break;
    if (text[cursor] !== '{')
      throw new Error('Go module output is not a JSON object stream.');
    const start = cursor;
    let depth = 0;
    let quoted = false;
    let escaped = false;
    for (; cursor < text.length; cursor++) {
      const char = text[cursor] ?? '';
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === '\\') escaped = true;
        else if (char === '"') quoted = false;
        continue;
      }
      if (char === '"') quoted = true;
      else if (char === '{') depth++;
      else if (char === '}') {
        depth--;
        if (depth === 0) {
          cursor++;
          break;
        }
      }
    }
    if (depth !== 0 || quoted)
      throw new Error('Go module output contains truncated JSON.');
    const parsed: unknown = JSON.parse(text.slice(start, cursor));
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      typeof (parsed as Record<string, unknown>).Path !== 'string'
    )
      throw new Error('Go module output contains an invalid record.');
    records.push(parsed as Record<string, unknown>);
    if (records.length > 100_000)
      throw new Error('Go module count exceeds its configured budget.');
  }
  if (records.length === 0)
    throw new Error('Go module output contains no resolved modules.');
  return records;
}
