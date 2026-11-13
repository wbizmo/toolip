import { createHash } from 'node:crypto';
import path from 'node:path';
import type { AnalysisCoverage } from '../../contracts/analysis.js';
import type { Finding } from '../../contracts/finding.js';
import { coverageOf } from '../../contracts/analysis.js';
import { walkProjectFiles, type ProjectFile } from '../../core/file-walker.js';
import { TextFileReader } from '../../core/text-file-reader.js';
import { parse as parseYaml } from 'yaml';

export type MaliciousContentFile = Readonly<{ path: string; content: string }>;
export type MaliciousContentResult = Readonly<{
  findings: readonly Finding[];
  coverage: AnalysisCoverage;
  filesScanned: number;
  bytesScanned: number;
}>;

type Entry = {
  file: string;
  referenceBase: string;
  kind: string;
  automatic: boolean;
  references: Set<string>;
  suspicious: boolean;
  unknown: boolean;
};
const MAX_ANALYSIS_FILES = 100_000;
const MAX_ANALYSIS_BYTES = 256 * 1024 * 1024;
const MAX_ANALYSIS_FILE_BYTES = 2 * 1024 * 1024;
const MAX_ENTRYPOINTS = 10_000;
const MAX_REFERENCES_PER_ENTRY = 10_000;
const MAX_REFERENCE_WORK = 100_000;
const MAX_CACHED_CONTENT_ANALYSES = 1_024;
const MAX_CACHED_REFERENCES_PER_CONTENT = 256;
const contentAnalysisCache = new Map<
  string,
  Readonly<{ references?: readonly string[]; signals: readonly string[] }>
>();
const binaryExtensions = new Set([
  '7z',
  'a',
  'avi',
  'bin',
  'bmp',
  'bz2',
  'class',
  'dll',
  'dmg',
  'dylib',
  'exe',
  'gif',
  'gz',
  'ico',
  'iso',
  'jar',
  'jpeg',
  'jpg',
  'mkv',
  'mov',
  'mp3',
  'mp4',
  'o',
  'pdf',
  'png',
  'so',
  'tar',
  'wasm',
  'webp',
  'woff',
  'zip',
  'xz'
]);

/** Candidate classification ignores extension claims but excludes known binaries. */
export function shouldInspectMaliciousContent(
  relativePath: string,
  extension: string
): boolean {
  return (
    !binaryExtensions.has(extension.toLowerCase()) &&
    !relativePath.endsWith('.map')
  );
}
const executableReference =
  /(?:\bnode(?:\.exe)?\s+|\b(?:bash|sh|zsh|pwsh|powershell)(?:\.exe)?\s+(?:-File\s+)?|\bpython(?:3)?\s+|\bdeno\s+run\s+|\b(?:bun|ruby|perl|php)(?:\.exe)?\s+(?:run\s+)?|\bcmd(?:\.exe)?\s+\/(?:c|k)\s+)(["']?)([^\s"';&|]+)\1/giu;
const nodePreloadReference =
  /\bnode(?:\.exe)?\s+(?:--require|-r|--import|--loader)(?:=|\s+)(["']?)(\.{1,2}\/[^\s"';&|]+)\1/giu;
const nodeOptionsPreloadReference =
  /\bNODE_OPTIONS\s*=\s*["']?(?:--require|-r|--import|--loader)(?:=|\s+)(["']?)(\.{1,2}\/[^\s"';&|]+)\1/giu;
const directLocalExecutionReference =
  /(?:^|[;&|]\s*)(?:exec\s+)?(["']?)(\.{1,2}\/[^\s"';&|]+)\1/gmu;
const localImport =
  /(?:\bfrom\s*|\brequire\s*\(|\bimport\s*\(|\bimport\s+|\b(?:load|require)\s+)["'](\.{1,2}\/[^"']+)["']/gu;
const shellSourceReference =
  /(?:^|[;&|]\s*)(?:source|\.)\s+["']?((?:\.{1,2}\/)?[^\s"';&|]+)["']?/gmu;
const suspiciousPayload =
  /(?:\beval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)|new\s+Function\s*\(\s*(?:atob|Buffer\.from)|\b(?:atob|Buffer\.from)\s*\([^;\n]{0,200}[\s\S]{0,240}\b(?:eval|new\s+Function)\s*\(|\b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:sh|bash)|\b(?:Invoke-Expression|IEX)\s*\(?\s*(?:\(Invoke-WebRequest|\$env:))/iu;
const dynamicExecution =
  /(?:\beval\s*\(|\bnew\s+Function\s*\(|\bchild_process\.(?:exec|execSync)\s*\()/u;
const automaticScript =
  /\b(?:curl|wget)\b[^\n;&]{0,180}(?:\||;|&&)\s*(?:sh|bash)/iu;
const archiveExtraction = /\b(?:unzip|tar|7z|busybox\s+unzip)\b/iu;
const archiveExecutionTarget =
  /(?:\b(?:node(?:\.exe)?|bash|sh|zsh|pwsh|powershell|python(?:3)?|deno|bun|ruby|perl|php|cmd(?:\.exe)?)\b\s+(?:\/(?:c|k)\s+)?[^\s;&|]+|(?:^|[;&|]\s*)\.{1,2}\/[^\s;&|]+)/imu;
const credentialStoreAccess =
  /(?:keytar\.(?:getPassword|findPassword)|(?:security\s+find-(?:generic|internet)-password)|secret-tool\s+lookup|(?:cmdkey|vaultcmd)\s+\/list|(?:readFileSync|readFile|openSync|Get-Content|cat|type)\s*[^\n]{0,240}(?:\.aws[\\/]credentials|\.npmrc|\.docker[\\/]config\.json|\.ssh[\\/](?:id_rsa|id_ed25519)|Login Data|Local State|credential|token)|(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|GH_TOKEN|AZURE_CLIENT_SECRET))/iu;
const outboundTransfer =
  /(?:\b(?:curl|wget|nc|ncat|socat)\b|\b(?:fetch|axios\.(?:post|put)|https?\.request)\s*\(|Invoke-WebRequest|upload(?:File|String))/iu;
const startupPersistence =
  /(?:\bcrontab\s+-|\b(?:systemctl|launchctl)\s+(?:enable|load|bootstrap)|\.config[\\/]autostart|(?:\.bashrc|\.zshrc|\.profile|Startup[\\/])|(?:CurrentVersion[\\/]Run|HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run))/iu;
const supportedShebang =
  /^\uFEFF?#!\s*(?:(?:\/[\w.-]+)*\/)?(?:env\s+(?:-S\s+)?)?(?:node|deno|bun|python(?:3)?|ruby|perl|php|bash|sh|zsh|pwsh|powershell|cmd)(?:\.exe)?(?:\s|$)/iu;
const executableTextSignature =
  /(?:^|\n)\s*(?:import\s|export\s|(?:const|let|var)\s+\w|(?:async\s+)?function\s+\w|(?:curl|wget|eval|exec|source|\.\s+)[^\n]*)/u;

function hasArchiveExecution(source: string): boolean {
  return (
    archiveExtraction.test(source) &&
    archiveExecutionTarget.test(source) &&
    /(?:&&|;|\|\|)/u.test(source)
  );
}

/** Returns behavior labels without retaining or reporting matching source text. */
function behaviorSignals(source: string): string[] {
  const signals: string[] = [];
  if (suspiciousPayload.test(source))
    signals.push('encoded-or-download-execution');
  if (hasArchiveExecution(source))
    signals.push('archive-extraction-and-execution');
  if (credentialStoreAccess.test(source) && outboundTransfer.test(source))
    signals.push('credential-access-with-outbound-transfer');
  if (
    startupPersistence.test(source) &&
    (suspiciousPayload.test(source) || automaticScript.test(source))
  )
    signals.push('download-or-payload-with-startup-persistence');
  return signals;
}

/**
 * Discover statically assigned local command targets without evaluating shell.
 * Deliberately ignores ambiguous/reassigned, late and nonliteral values.
 * Each bounded file is walked twice: O(B) time and O(A + R) space for
 * B source units, A assignments and R references.
 */
function staticShellTargets(source: string): string[] {
  const assignments = new Map<
    string,
    { ambiguous?: boolean; value?: string; position?: number }
  >();
  // Only literal project-relative targets and exact, non-reassigned aliases
  // are accepted. No shell interpolation, sourcing or evaluation occurs.
  const assignmentPattern =
    /(?:^|[;\n])\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(["']?)(\.{1,2}\/[A-Za-z0-9_./-]+|\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*))\2(?=\s*(?:;|\n|$))/gmu;
  for (const match of source.matchAll(assignmentPattern)) {
    const name = match[1];
    if (!name) continue;
    const previous = assignments.get(name);
    // In POSIX shell, single quotes suppress parameter expansion.
    const singleQuotedAlias =
      match[2] === "'" && (match[3] ?? '').startsWith('$');
    assignments.set(
      name,
      previous || singleQuotedAlias
        ? { ambiguous: true }
        : { value: match[3], position: match.index ?? 0 }
    );
  }
  // Prevent cycles and computational amplification from malicious aliases.
  const resolveTarget = (
    name: string,
    before: number,
    visited: Set<string>,
    depth: number
  ): string | undefined => {
    if (depth > 16 || visited.has(name)) return undefined;
    const assignment = assignments.get(name);
    if (
      !assignment ||
      assignment.ambiguous ||
      assignment.position === undefined ||
      assignment.position >= before ||
      !assignment.value
    )
      return undefined;
    if (/^\.{1,2}\/[A-Za-z0-9_./-]+$/u.test(assignment.value))
      return assignment.value;
    const alias = assignment.value.match(
      /^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$/u
    );
    const aliasName = alias?.[1] ?? alias?.[2];
    if (!aliasName) return undefined;
    visited.add(name);
    return resolveTarget(aliasName, assignment.position, visited, depth + 1);
  };
  const targets = new Set<string>();
  const executionPattern =
    /\b(?:node(?:\.exe)?|bash|sh|zsh|python(?:3)?|ruby|perl|php|bun)(?:\.exe)?\s+(?:"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*))(?=\s|[;&|]|$)/gmu;
  for (const match of source.matchAll(executionPattern)) {
    const name = match[1] ?? match[2] ?? match[3] ?? match[4];
    if (!name) continue;
    const target = resolveTarget(name, match.index ?? 0, new Set(), 0);
    if (target) targets.add(target);
  }
  return [...targets].sort();
}

/** Reuses source-derived signals and path-neutral references by exact content hash. */
function contentAnalysis(source: string): Readonly<{
  references?: readonly string[];
  signals: readonly string[];
}> {
  const digest = createHash('sha256').update(source).digest('hex');
  const cached = contentAnalysisCache.get(digest);
  if (cached) {
    contentAnalysisCache.delete(digest);
    contentAnalysisCache.set(digest, cached);
    return cached;
  }
  const references = new Set<string>();
  const patterns = [
    executableReference,
    nodePreloadReference,
    nodeOptionsPreloadReference,
    directLocalExecutionReference,
    localImport,
    shellSourceReference
  ];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    for (const match of source.matchAll(pattern)) {
      const value =
        pattern === executableReference ||
        pattern === nodePreloadReference ||
        pattern === nodeOptionsPreloadReference ||
        pattern === directLocalExecutionReference
          ? match[2]
          : match[1];
      if (value) references.add(value);
      if (references.size > MAX_CACHED_REFERENCES_PER_CONTENT) break;
    }
    if (references.size > MAX_CACHED_REFERENCES_PER_CONTENT) break;
  }
  for (const target of staticShellTargets(source)) references.add(target);
  const result = Object.freeze({
    ...(references.size <= MAX_CACHED_REFERENCES_PER_CONTENT
      ? { references: Object.freeze([...references].sort()) }
      : {}),
    signals: Object.freeze(behaviorSignals(source))
  });
  contentAnalysisCache.set(digest, result);
  if (contentAnalysisCache.size > MAX_CACHED_CONTENT_ANALYSES) {
    const oldest = contentAnalysisCache.keys().next().value;
    if (oldest !== undefined) contentAnalysisCache.delete(oldest);
  }
  return result;
}

function stableId(parts: readonly string[]): string {
  return createHash('sha256')
    .update(parts.join('\0'))
    .digest('hex')
    .slice(0, 24);
}

/**
 * Read the JSONC subset used by VS Code tasks: comments and trailing commas.
 * Quoted strings stay byte-for-byte intact; unterminated comments fail closed.
 * O(B) time and O(B) space for B input code units under caller byte limits.
 */
function parseEditorTaskJsonc(source: string): unknown {
  const chars = source.split('');
  let inString = false;
  let escaped = false;
  for (let i = 0; i < chars.length; i++) {
    const char = chars[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      continue;
    }
    if (char === '/' && chars[i + 1] === '/') {
      chars[i++] = ' ';
      chars[i] = ' ';
      while (
        i + 1 < chars.length &&
        chars[i + 1] !== '\n' &&
        chars[i + 1] !== '\r'
      )
        chars[++i] = ' ';
    } else if (char === '/' && chars[i + 1] === '*') {
      chars[i++] = ' ';
      chars[i] = ' ';
      let terminated = false;
      while (++i < chars.length) {
        const current = chars[i];
        chars[i] = current === '\n' || current === '\r' ? current : ' ';
        if (current === '*' && chars[i + 1] === '/') {
          chars[++i] = ' ';
          terminated = true;
          break;
        }
      }
      if (!terminated) throw new SyntaxError('Unterminated JSONC comment');
    }
  }
  inString = false;
  escaped = false;
  for (let i = 0; i < chars.length; i++) {
    const char = chars[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
    } else if (char === ',') {
      let next = i + 1;
      while (next < chars.length && /\s/u.test(chars[next])) next++;
      if (chars[next] === '}' || chars[next] === ']') chars[i] = ' ';
    }
  }
  return JSON.parse(chars.join(''));
}

function safeJson(content: string): unknown {
  try {
    return JSON.parse(content) as unknown;
  } catch {
    return undefined;
  }
}

function extensionlessTargetIndex(
  files: readonly MaliciousContentFile[]
): Map<string, string[]> {
  const index = new Map<string, string[]>();
  for (const file of files) {
    const extension = path.posix.extname(file.path);
    if (!extension) continue;
    const stem = file.path.slice(0, -extension.length);
    const candidates = index.get(stem) ?? [];
    candidates.push(file.path);
    index.set(stem, candidates);
  }
  return index;
}

function malformedEntrypoint(file: MaliciousContentFile): boolean {
  if (
    file.path !== 'package.json' &&
    !file.path.endsWith('/package.json') &&
    file.path !== '.vscode/tasks.json' &&
    !file.path.endsWith('/.vscode/tasks.json') &&
    !/^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(file.path)
  )
    return false;
  if (/^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(file.path)) {
    try {
      const workflow = parseYaml(file.content, { maxAliasCount: 100 });
      return !workflow || typeof workflow !== 'object';
    } catch {
      return true;
    }
  }
  let parsed: unknown;
  try {
    parsed = file.path.endsWith('/tasks.json')
      ? parseEditorTaskJsonc(file.content)
      : safeJson(file.content);
  } catch {
    return true;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
    return true;
  const record = parsed as Record<string, unknown>;
  if (file.path === 'package.json' || file.path.endsWith('/package.json')) {
    const scripts = record.scripts;
    return (
      scripts !== undefined &&
      (!scripts ||
        typeof scripts !== 'object' ||
        Array.isArray(scripts) ||
        Object.values(scripts).some((value) => typeof value !== 'string'))
    );
  }
  return (
    !Array.isArray(record.tasks) ||
    record.tasks.some((task) => {
      if (!task || typeof task !== 'object' || Array.isArray(task)) return true;
      const value = task as Record<string, unknown>;
      const runOptions = value.runOptions;
      return (
        (value.command !== undefined && typeof value.command !== 'string') ||
        (value.script !== undefined && typeof value.script !== 'string') ||
        (value.args !== undefined &&
          (!Array.isArray(value.args) ||
            value.args.some((part) => typeof part !== 'string'))) ||
        (runOptions !== undefined &&
          (!runOptions ||
            typeof runOptions !== 'object' ||
            Array.isArray(runOptions) ||
            ((runOptions as { runOn?: unknown }).runOn !== undefined &&
              !['default', 'folderOpen'].includes(
                String((runOptions as { runOn?: unknown }).runOn)
              ))))
      );
    })
  );
}

function safeDisplayPath(value: string): string {
  return value.replace(/\p{Cc}/gu, '?').slice(0, 512);
}

function scriptEntries(files: readonly MaliciousContentFile[]): {
  entries: Entry[];
  truncated: boolean;
} {
  const entries: Entry[] = [];
  let truncated = false;
  const addEntry = (entry: Entry) => {
    if (entries.length >= MAX_ENTRYPOINTS) {
      truncated = true;
      return;
    }
    entries.push(entry);
  };
  const addReference = (references: Set<string>, reference: string) => {
    if (references.has(reference)) return;
    if (references.size >= MAX_REFERENCES_PER_ENTRY) {
      truncated = true;
      return;
    }
    references.add(reference);
  };
  const addExecutableReferences = (source: string, references: Set<string>) => {
    const analyzed = contentAnalysis(source).references;
    if (analyzed) {
      for (const reference of analyzed) addReference(references, reference);
      return;
    }
    executableReference.lastIndex = 0;
    for (const match of source.matchAll(executableReference))
      addReference(references, match[2] ?? '');
    directLocalExecutionReference.lastIndex = 0;
    for (const match of source.matchAll(directLocalExecutionReference))
      addReference(references, match[2] ?? '');
    for (const pattern of [nodePreloadReference, nodeOptionsPreloadReference]) {
      pattern.lastIndex = 0;
      for (const match of source.matchAll(pattern))
        addReference(references, match[2] ?? '');
    }
    for (const target of staticShellTargets(source))
      addReference(references, target);
  };
  for (const file of files) {
    if (file.path !== 'package.json' && !file.path.endsWith('/package.json'))
      continue;
    const manifest = safeJson(file.content);
    if (manifest && typeof manifest === 'object' && !Array.isArray(manifest)) {
      const scripts = (manifest as { scripts?: unknown }).scripts;
      if (scripts && typeof scripts === 'object' && !Array.isArray(scripts)) {
        for (const [name, value] of Object.entries(scripts)) {
          if (typeof value !== 'string') continue;
          const refs = new Set<string>();
          addExecutableReferences(value, refs);
          addEntry({
            file: file.path,
            referenceBase: file.path,
            kind: `npm-script:${name}`,
            automatic: [
              'prepare',
              'preinstall',
              'install',
              'postinstall',
              'prepack'
            ].includes(name),
            references: refs,
            suspicious:
              contentAnalysis(value).signals.length > 0 ||
              automaticScript.test(value),
            unknown: dynamicExecution.test(value) && refs.size === 0
          });
        }
      }
    }
  }

  for (const file of files) {
    if (
      file.path !== '.vscode/tasks.json' &&
      !file.path.endsWith('/.vscode/tasks.json')
    )
      continue;
    let tasks: unknown;
    try {
      tasks = parseEditorTaskJsonc(file.content);
    } catch {
      continue; // malformedEntrypoint() marks this input incomplete
    }
    if (tasks && typeof tasks === 'object' && !Array.isArray(tasks)) {
      const taskList = (tasks as { tasks?: unknown }).tasks;
      if (Array.isArray(taskList))
        for (const task of taskList) {
          if (!task || typeof task !== 'object') continue;
          const object = task as {
            runOn?: unknown;
            runOptions?: unknown;
            command?: unknown;
            script?: unknown;
            args?: unknown;
            type?: unknown;
          };
          const source = [
            object.command,
            object.script,
            ...(Array.isArray(object.args) ? object.args : [])
          ]
            .filter((v): v is string => typeof v === 'string')
            .join(' ');
          const runOptions =
            object.runOptions &&
            typeof object.runOptions === 'object' &&
            !Array.isArray(object.runOptions)
              ? (object.runOptions as { runOn?: unknown })
              : undefined;
          const automatic =
            object.runOn === 'folderOpen' || runOptions?.runOn === 'folderOpen';
          const refs = new Set<string>();
          addExecutableReferences(source, refs);
          if (object.type === 'npm' && typeof object.script === 'string')
            addReference(refs, 'package.json');
          if (automatic || refs.size || dynamicExecution.test(source))
            addEntry({
              file: file.path,
              referenceBase: path.posix.join(
                path.posix.dirname(file.path),
                '..',
                'package.json'
              ),
              kind: 'editor-task',
              automatic,
              references: refs,
              suspicious:
                contentAnalysis(source).signals.length > 0 ||
                automaticScript.test(source),
              unknown: dynamicExecution.test(source) && refs.size === 0
            });
        }
    }
  }

  for (const file of files) {
    if (
      /(?:^|\/)(?:eslint(?:\.config)?|\.eslintrc|vite\.config|webpack\.config|rollup\.config|\.vscode\/settings)\b/iu.test(
        file.path
      )
    ) {
      const refs = new Set<string>();
      localImport.lastIndex = 0;
      for (const match of file.content.matchAll(localImport))
        addReference(refs, match[1] ?? '');
      if (
        refs.size ||
        suspiciousPayload.test(file.content) ||
        dynamicExecution.test(file.content)
      )
        addEntry({
          file: file.path,
          referenceBase: file.path,
          kind: 'tool-config',
          automatic: true,
          references: refs,
          suspicious: contentAnalysis(file.content).signals.length > 0,
          unknown: dynamicExecution.test(file.content) && refs.size === 0
        });
    }
  }

  // Git hooks are executable entrypoints. Inspect tracked snapshot text only;
  // never invoke a hook or trust its extension when deciding to scan it.
  for (const file of files) {
    if (!/(?:^|\/)\.husky\/[^/]+$/u.test(file.path)) continue;
    const refs = new Set<string>();
    addExecutableReferences(file.content, refs);
    shellSourceReference.lastIndex = 0;
    for (const match of file.content.matchAll(shellSourceReference))
      addReference(refs, match[1] ?? '');
    addEntry({
      file: file.path,
      referenceBase: 'package.json',
      kind: 'git-hook',
      automatic: true,
      references: refs,
      suspicious:
        contentAnalysis(file.content).signals.length > 0 ||
        automaticScript.test(file.content),
      unknown: dynamicExecution.test(file.content) && refs.size === 0
    });
  }

  // Parse workflow YAML as data and inspect every run step. GitHub defaults to
  // the repository root; explicit dynamic working directories stay unknown.
  for (const file of files) {
    if (!/^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(file.path)) continue;
    let workflow: unknown;
    try {
      workflow = parseYaml(file.content, { maxAliasCount: 100 });
    } catch {
      continue; // malformedEntrypoint() marks this input incomplete
    }
    if (!workflow || typeof workflow !== 'object' || Array.isArray(workflow))
      continue;
    const jobs = (workflow as { jobs?: unknown }).jobs;
    if (!jobs || typeof jobs !== 'object' || Array.isArray(jobs)) continue;
    for (const job of Object.values(jobs)) {
      if (!job || typeof job !== 'object' || Array.isArray(job)) continue;
      const jobValue = job as {
        steps?: unknown;
        defaults?: { run?: { 'working-directory'?: unknown } };
      };
      if (!Array.isArray(jobValue.steps)) continue;
      for (const step of jobValue.steps) {
        if (!step || typeof step !== 'object' || Array.isArray(step)) continue;
        const value = step as {
          run?: unknown;
          'working-directory'?: unknown;
        };
        if (typeof value.run !== 'string') continue;
        const refs = new Set<string>();
        addExecutableReferences(value.run, refs);
        shellSourceReference.lastIndex = 0;
        for (const match of value.run.matchAll(shellSourceReference))
          addReference(refs, match[1] ?? '');
        const cwd =
          value['working-directory'] ??
          jobValue.defaults?.run?.['working-directory'];
        const dynamicCwd = cwd !== undefined && typeof cwd !== 'string';
        addEntry({
          file: file.path,
          referenceBase:
            typeof cwd === 'string' && cwd.length > 0
              ? path.posix.join(cwd, 'package.json')
              : 'package.json',
          kind: 'github-actions-run',
          automatic: true,
          references: refs,
          suspicious:
            contentAnalysis(value.run).signals.length > 0 ||
            automaticScript.test(value.run),
          unknown:
            dynamicCwd || (dynamicExecution.test(value.run) && refs.size === 0)
        });
      }
    }
  }
  const contentByPath = new Map(files.map((file) => [file.path, file.content]));
  const disguisedTargets = extensionlessTargetIndex(files);
  const knownEntrypoints = new Set(entries.map((entry) => entry.file));
  const reachableFiles = new Set<string>();
  const referenceQueue: Array<readonly [string, string]> = [];
  for (const entry of entries) {
    for (const reference of entry.references) {
      if (referenceQueue.length >= MAX_REFERENCE_WORK) {
        truncated = true;
        break;
      }
      referenceQueue.push([entry.referenceBase, reference]);
    }
    if (truncated) break;
  }
  const visitedReferences = new Set<string>();
  for (let cursor = 0; cursor < referenceQueue.length; cursor++) {
    if (cursor >= MAX_REFERENCE_WORK) {
      truncated = true;
      break;
    }
    const item = referenceQueue[cursor];
    if (!item) continue;
    const [from, reference] = item;
    const key = `${from}\0${reference}`;
    if (visitedReferences.has(key)) continue;
    visitedReferences.add(key);
    const target = resolveLocalReference(
      from,
      reference,
      contentByPath,
      disguisedTargets
    );
    if (!target || reachableFiles.has(target)) continue;
    reachableFiles.add(target);
    const source = contentByPath.get(target) ?? '';
    const nested = new Set<string>();
    const cachedReferences = contentAnalysis(source).references;
    if (cachedReferences) {
      for (const reference of cachedReferences) addReference(nested, reference);
    } else {
      addExecutableReferences(source, nested);
      localImport.lastIndex = 0;
      for (const match of source.matchAll(localImport))
        addReference(nested, match[1] ?? '');
      shellSourceReference.lastIndex = 0;
      for (const match of source.matchAll(shellSourceReference))
        addReference(nested, match[1] ?? '');
    }
    for (const child of nested) {
      if (referenceQueue.length >= MAX_REFERENCE_WORK) {
        truncated = true;
        break;
      }
      referenceQueue.push([target, child]);
    }
    if (truncated) break;
  }
  // Content signatures supplement path-based discovery without duplicating
  // traces already rooted in a recognized manifest, task, hook, config or CI
  // entrypoint. Unknown executable names are still considered by shebang and
  // source-language signatures, never by extension or MIME claims alone.
  for (const file of files) {
    if (
      knownEntrypoints.has(file.path) ||
      reachableFiles.has(file.path) ||
      file.path === 'package.json' ||
      file.path.endsWith('/package.json') ||
      file.path === '.vscode/tasks.json' ||
      file.path.endsWith('/.vscode/tasks.json') ||
      /^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(file.path) ||
      /(?:^|\/)\.husky\/[^/]+$/u.test(file.path)
    )
      continue;
    const shebang = supportedShebang.test(
      file.content.split(/\r?\n/u, 1)[0] ?? ''
    );
    const signals = contentAnalysis(file.content).signals;
    if (
      !shebang &&
      !(signals.length > 0 && executableTextSignature.test(file.content))
    )
      continue;
    const refs = new Set<string>();
    addExecutableReferences(file.content, refs);
    localImport.lastIndex = 0;
    for (const match of file.content.matchAll(localImport))
      addReference(refs, match[1] ?? '');
    shellSourceReference.lastIndex = 0;
    for (const match of file.content.matchAll(shellSourceReference))
      addReference(refs, match[1] ?? '');
    addEntry({
      file: file.path,
      referenceBase: file.path,
      kind: shebang ? 'shebang-script' : 'content-signature-script',
      automatic: false,
      references: refs,
      suspicious: signals.length > 0,
      unknown: dynamicExecution.test(file.content) && refs.size === 0
    });
  }
  return { entries, truncated };
}

function resolveLocalReference(
  from: string,
  reference: string,
  files: ReadonlyMap<string, string>,
  disguisedTargets: ReadonlyMap<string, readonly string[]>
): string | undefined {
  if (
    !reference ||
    path.isAbsolute(reference) ||
    reference.includes('\\') ||
    reference.includes('\0')
  )
    return undefined;
  const candidate = path.posix
    .normalize(path.posix.join(path.posix.dirname(from), reference))
    .replace(/^\.\//u, '');
  if (candidate === '..' || candidate.startsWith('../')) return undefined;
  const candidates = [
    candidate,
    ...[
      '.js',
      '.cjs',
      '.mjs',
      '.jsx',
      '.ts',
      '.tsx',
      '.sh',
      '.ps1',
      '.py',
      '.rb',
      '.pl',
      '.php',
      '.cmd',
      '.bat'
    ].map((suffix) => `${candidate}${suffix}`),
    ...['index.js', 'index.ts', 'index.sh'].map(
      (name) => `${candidate}/${name}`
    )
  ];
  const direct = candidates.find((item) => files.has(item));
  if (direct) return direct;
  const disguised = disguisedTargets.get(candidate) ?? [];
  return disguised.length === 1 ? disguised[0] : undefined;
}

/**
 * Non-executing heuristic discovery for automatic entrypoints and cross-file
 * execution chains. With F files, B bytes, and graph (V,E), discovery and
 * traversal are O(F+B+V+E); peak memory is O(F+B+V+E), bounded by the caller's
 * file and byte budgets. Confidence is signal-based, never proof of malware.
 */
export function analyzeMaliciousContent(
  files: readonly MaliciousContentFile[]
): MaliciousContentResult {
  const orderedFiles = [...files].sort((left, right) =>
    left.path.localeCompare(right.path)
  );
  const selectedFiles: MaliciousContentFile[] = [];
  const paths = new Set<string>();
  let bytesSelected = 0;
  for (const file of orderedFiles) {
    const bytes = Buffer.byteLength(file.content);
    if (
      paths.has(file.path) ||
      selectedFiles.length >= MAX_ANALYSIS_FILES ||
      bytes > MAX_ANALYSIS_FILE_BYTES ||
      bytesSelected + bytes > MAX_ANALYSIS_BYTES
    )
      continue;
    paths.add(file.path);
    selectedFiles.push(file);
    bytesSelected += bytes;
  }
  const content = new Map(
    selectedFiles.map((file) => [file.path, file.content])
  );
  const disguisedTargets = extensionlessTargetIndex(selectedFiles);
  const malformed = selectedFiles.filter(malformedEntrypoint).length;
  const entryResult = scriptEntries(selectedFiles);
  const findings: Finding[] = [];
  let referenceWork = 0;
  let workExhausted = false;
  for (const entry of entryResult.entries) {
    if (workExhausted) break;
    const trace = [entry.file];
    const queue = [...entry.references].map(
      (reference) => [entry.referenceBase, reference] as const
    );
    let dynamicUnknown = entry.unknown;
    const signals = new Set(
      contentAnalysis(content.get(entry.file) ?? '').signals
    );
    const enqueue = (from: string, reference: string) => {
      if (queue.length >= MAX_REFERENCE_WORK) {
        workExhausted = true;
        dynamicUnknown = true;
        return false;
      }
      queue.push([from, reference]);
      return true;
    };
    const seen = new Set<string>();
    let payload = entry.suspicious;
    for (let cursor = 0; cursor < queue.length; cursor++) {
      if (++referenceWork > MAX_REFERENCE_WORK) {
        workExhausted = true;
        dynamicUnknown = true;
        break;
      }
      const item = queue[cursor];
      if (!item) continue;
      const [from, reference] = item;
      const referenceKey = `${from}\0${reference}`;
      if (!reference || seen.has(referenceKey)) continue;
      seen.add(referenceKey);
      const target = resolveLocalReference(
        from,
        reference,
        content,
        disguisedTargets
      );
      if (!target) {
        dynamicUnknown = true;
        continue;
      }
      trace.push(target);
      const targetText = content.get(target) ?? '';
      for (const signal of contentAnalysis(targetText).signals)
        signals.add(signal);
      if (signals.size > 0 || automaticScript.test(targetText)) payload = true;
      const nestedReferences = contentAnalysis(targetText).references;
      if (nestedReferences) {
        for (const nested of nestedReferences)
          if (!enqueue(target, nested)) break;
      } else {
        localImport.lastIndex = 0;
        for (const match of targetText.matchAll(localImport)) {
          const nested = match[1];
          if (nested && !enqueue(target, nested)) break;
        }
        shellSourceReference.lastIndex = 0;
        for (const match of targetText.matchAll(shellSourceReference)) {
          const nested = match[1];
          if (nested && !enqueue(target, nested)) break;
        }
        executableReference.lastIndex = 0;
        for (const match of targetText.matchAll(executableReference)) {
          const nested = match[2];
          if (nested && !enqueue(target, nested)) break;
        }
        directLocalExecutionReference.lastIndex = 0;
        for (const match of targetText.matchAll(
          directLocalExecutionReference
        )) {
          const nested = match[2];
          if (nested && !enqueue(target, nested)) break;
        }
        for (const pattern of [
          nodePreloadReference,
          nodeOptionsPreloadReference
        ]) {
          pattern.lastIndex = 0;
          for (const match of targetText.matchAll(pattern)) {
            const nested = match[2];
            if (nested && !enqueue(target, nested)) break;
          }
        }
        for (const nested of staticShellTargets(targetText))
          if (!enqueue(target, nested)) break;
      }
    }
    // Unknown references stay review leads unless suspicious behavior is also
    // present. Automatic entrypoints or multi-file traces raise a positive
    // payload signal; automation alone is not a malicious-content indicator.
    const elevated = payload && (entry.automatic || trace.length > 1);
    if (!payload && !dynamicUnknown) continue;
    const confidence = elevated ? 'high' : 'low';
    const ruleId = payload ? 'TLP-MAL-001' : 'TLP-MAL-002';
    const traceDisplay = trace.map(safeDisplayPath);
    findings.push({
      id: stableId([ruleId, entry.file, entry.kind, ...[...trace].sort()]),
      ruleId,
      title: payload
        ? 'Suspicious automatic execution chain'
        : 'Unresolved dynamic execution reference',
      category: 'malicious-content',
      severity: elevated ? 'high' : 'medium',
      confidence,
      message: payload
        ? 'An automatic entrypoint is connected to behavior associated with encoded execution, credential transfer, persistence, archive execution, or download-and-execute chains. Review the trace before running repository scripts.'
        : 'An execution entrypoint contains a dynamic or unresolved reference; static analysis cannot establish the target behavior.',
      source: 'malicious-content-static-analysis',
      location: { file: safeDisplayPath(entry.file) },
      evidence: [
        {
          summary: `Static trace: ${traceDisplay.slice(0, 20).join(' -> ')}${trace.length > 20 ? ' -> …' : ''}`
        }
      ],
      metadata: {
        entrypointKind: safeDisplayPath(entry.kind),
        automatic: entry.automatic,
        trace: traceDisplay,
        behaviorSignals: [...signals].sort(),
        completeness: dynamicUnknown ? 'unknown' : 'analyzed'
      }
    });
    if (workExhausted) break;
  }
  const budgetSkipped =
    (workExhausted || entryResult.truncated) && selectedFiles.length > malformed
      ? 1
      : 0;
  const scanned = Math.max(0, selectedFiles.length - malformed - budgetSkipped);
  return Object.freeze({
    findings: Object.freeze(
      findings.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    ),
    coverage: coverageOf({
      eligible: files.length,
      scanned,
      skipped: Math.max(0, files.length - scanned),
      failed: 0
    }),
    filesScanned: scanned,
    bytesScanned: bytesSelected
  });
}

/** Reads bounded non-binary files from an already discovered immutable listing. */
export async function scanMaliciousContent(
  root: string,
  signal?: AbortSignal,
  discoveredFiles?: readonly ProjectFile[],
  knownContent: ReadonlyMap<string, string> = new Map(),
  allowUnseenReads = true,
  knownBinaryPaths: ReadonlySet<string> = new Set()
): Promise<MaliciousContentResult> {
  const files = discoveredFiles ?? (await walkProjectFiles(root));
  const reader = new TextFileReader(undefined, { root });
  const contents: MaliciousContentFile[] = [];
  let skipped = 0;
  let failed = 0;
  let eligible = 0;
  let bytesScanned = 0;
  for (const file of files) {
    if (!shouldInspectMaliciousContent(file.relativePath, file.extension))
      continue;
    // Immutable snapshots already classified these bytes. Preserve the
    // scanner's normal binary exclusion without trying to decode the file or
    // treating a known binary as an incomplete text scan.
    if (knownBinaryPaths.has(file.relativePath)) {
      // Known binary extensions are deliberate exclusions. An unrecognized
      // extension that snapshot classification finds binary may be a disguised
      // executable/archive; count it as eligible but incomplete instead of
      // claiming the malicious-content pass scanned every candidate.
      if (!binaryExtensions.has(file.extension.toLowerCase())) {
        eligible++;
        skipped++;
      }
      continue;
    }
    eligible++;
    const priorContent = knownContent.get(file.relativePath);
    if (priorContent !== undefined) {
      contents.push({ path: file.relativePath, content: priorContent });
      bytesScanned += Buffer.byteLength(priorContent);
      continue;
    }
    if (!allowUnseenReads) {
      skipped++;
      continue;
    }
    const result = await reader.read(file.absolutePath, signal, file.snapshot);
    if (result.status === 'binary') {
      skipped++;
      continue;
    }
    if (result.status !== 'ok') {
      if (result.status === 'failed') failed++;
      else skipped++;
      continue;
    }
    bytesScanned += result.bytes;
    contents.push({ path: file.relativePath, content: result.content });
  }
  const analysis = analyzeMaliciousContent(contents);
  return Object.freeze({
    ...analysis,
    coverage: coverageOf({
      eligible,
      scanned: contents.length - analysis.coverage.skipped,
      skipped: skipped + analysis.coverage.skipped,
      failed,
      cancelled: signal?.aborted
    }),
    bytesScanned
  });
}
