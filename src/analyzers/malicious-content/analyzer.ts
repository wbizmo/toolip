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
  signals: readonly string[];
  suspicious: boolean;
  unknown: boolean;
};
// Covers the explicit 250k qualification fixture plus its bounded metadata
// files. Byte, entrypoint and graph-work budgets remain independent caps.
const MAX_ANALYSIS_FILES = 250_010;
const MAX_ANALYSIS_BYTES = 256 * 1024 * 1024;
const MAX_ANALYSIS_FILE_BYTES = 2 * 1024 * 1024;
const MAX_BINARY_NAMED_TEXT_PROBES = 256;
const MAX_ENTRYPOINTS = 10_000;
const MAX_REFERENCES_PER_ENTRY = 10_000;
const MAX_REFERENCE_WORK = 100_000;
const MAX_REPORTED_TRACE_PATHS = 64;
const MAX_CACHED_CONTENT_ANALYSES = 1_024;
const MAX_CACHED_REFERENCES_PER_CONTENT = 256;
const contentAnalysisCache = new Map<
  string,
  Readonly<{
    references?: readonly string[];
    signals: readonly string[];
    unresolvedShellCommand: boolean;
    dynamicExecution: boolean;
    archiveExtracts: boolean;
    archiveLaunches: boolean;
  }>
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

export function isKnownMaliciousBinaryExtension(extension: string): boolean {
  return binaryExtensions.has(extension.toLowerCase());
}

/** A filename extension is not content proof. Confirm binary status from bytes. */
export function shouldInspectMaliciousContent(
  relativePath: string,
  _extension: string
): boolean {
  return !relativePath.endsWith('.map');
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
const packageScriptReference =
  /\b(?:npm|pnpm|yarn)\s+(?:run|run-script)\s+(?:"([^"\n]+)"|'([^'\n]+)'|([^\s;&|]+))/giu;
const workspaceScriptReference =
  /\b(?:npm\s+(?:--workspace(?:=|\s+)|--prefix(?:=|\s+)|-w\s+)([^\s]+)\s+(?:run|run-script)\s+([^\s;&|]+)|npm\s+(?:run|run-script)\s+([^\s;&|]+)\s+--(?:workspace|prefix)(?:=|\s+)([^\s;&|]+)|pnpm\s+--filter(?:=|\s+)([^\s]+)\s+(?:run\s+)?([^\s;&|]+)|yarn\s+workspace\s+([^\s]+)\s+([^\s;&|]+))/giu;
const suspiciousPayload =
  /(?:\beval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)|new\s+Function\s*\(\s*(?:atob|Buffer\.from)|\b(?:atob|Buffer\.from)\s*\([^;\n]{0,200}[\s\S]{0,240}\b(?:eval|new\s+Function)\s*\(|\b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:sh|bash)|\b(?:Invoke-Expression|IEX)\s*\(?\s*(?:\(Invoke-WebRequest|\$env:))/iu;
const encodedInterpreterLoader =
  /(?:\b(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b|\b(?:pwsh|powershell)(?:\.exe)?\b[^\r\n]{0,128}\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\b(?:node|deno|bun)\s+(?:-e|--eval)\s+['"][^\r\n]{0,128}\b(?:atob|Buffer\.from)\s*\()/iu;
const dynamicExecution =
  /(?:\beval\s*\(|\bnew\s+Function\s*\(|\b(?:node:)?child_process\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\()/u;
const childProcessFunctions = new Set([
  'exec',
  'execSync',
  'execFile',
  'execFileSync',
  'spawn',
  'spawnSync',
  'fork'
]);
const childProcessModule = /^(?:node:)?child_process$/u;

function hasDynamicExecution(source: string): boolean {
  if (
    dynamicExecution.test(source) ||
    archiveApiExecution.test(source) ||
    /\bStart-Process\b/u.test(source) ||
    /\b(?:import|require)\s*\(\s*(?!['"])/u.test(source)
  )
    return true;

  const functionAliases = new Set<string>();
  const namespaceAliases = new Set<string>();
  const namedImport = /\bimport\s*\{([^}]*)\}\s*from\s*(['"])([^'"]+)\2/gu;
  for (const match of source.matchAll(namedImport)) {
    if (!childProcessModule.test(match[3] ?? '')) continue;
    for (const specifier of (match[1] ?? '').split(',')) {
      const parts = specifier.trim().split(/\s+as\s+/u);
      const imported = parts[0]?.trim();
      const local = parts[1]?.trim() ?? imported;
      if (imported && local && childProcessFunctions.has(imported))
        functionAliases.add(local);
    }
  }

  const cjsDestructure =
    /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*(['"])([^'"]+)\2\s*\)/gu;
  for (const match of source.matchAll(cjsDestructure)) {
    if (!childProcessModule.test(match[3] ?? '')) continue;
    for (const specifier of (match[1] ?? '').split(',')) {
      const parts = specifier.trim().split(/\s*:\s*/u);
      const imported = parts[0]?.trim();
      const local = parts[1]?.trim() ?? imported;
      if (imported && local && childProcessFunctions.has(imported))
        functionAliases.add(local);
    }
  }
  const dynamicImportDestructure =
    /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?import\(\s*(['"])([^'"]+)\2\s*\)/gu;
  for (const match of source.matchAll(dynamicImportDestructure)) {
    if (!childProcessModule.test(match[3] ?? '')) continue;
    for (const specifier of (match[1] ?? '').split(',')) {
      const parts = specifier.trim().split(/\s*:\s*/u);
      const imported = parts[0]?.trim();
      const local = parts[1]?.trim() ?? imported;
      if (imported && local && childProcessFunctions.has(imported))
        functionAliases.add(local);
    }
  }

  const namespaceImport =
    /\bimport\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s+from\s*(['"])([^'"]+)\2/gu;
  for (const match of source.matchAll(namespaceImport))
    if (childProcessModule.test(match[3] ?? '') && match[1])
      namespaceAliases.add(match[1]);

  const defaultImport =
    /\bimport\s+([A-Za-z_$][\w$]*)\s+from\s*(['"])([^'"]+)\2/gu;
  for (const match of source.matchAll(defaultImport))
    if (childProcessModule.test(match[3] ?? '') && match[1])
      namespaceAliases.add(match[1]);

  const cjsNamespace =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*(['"])([^'"]+)\2\s*\)/gu;
  for (const match of source.matchAll(cjsNamespace))
    if (childProcessModule.test(match[3] ?? '') && match[1])
      namespaceAliases.add(match[1]);
  const dynamicNamespace =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?import\(\s*(['"])([^'"]+)\2\s*\)/gu;
  for (const match of source.matchAll(dynamicNamespace))
    if (childProcessModule.test(match[3] ?? '') && match[1])
      namespaceAliases.add(match[1]);

  const apiAliases =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:([A-Za-z_$][\w$]*)\s*\.\s*(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)|([A-Za-z_$][\w$]*))\s*(?=[;,\n])/gu;
  for (const match of source.matchAll(apiAliases)) {
    const alias = match[1];
    const namespace = match[2];
    const method = match[3];
    const sourceAlias = match[4];
    if (
      alias &&
      ((namespace && namespaceAliases.has(namespace) && method) ||
        (sourceAlias && functionAliases.has(sourceAlias)))
    )
      functionAliases.add(alias);
  }

  if (functionAliases.size) {
    const reflectiveCall =
      /\bReflect\s*\.\s*(?:apply|construct)\s*\(\s*([A-Za-z_$][\w$]*)\s*,/gu;
    for (const match of source.matchAll(reflectiveCall))
      if (functionAliases.has(match[1] ?? '')) return true;
    const indirectCall = /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:apply|call)\s*\(/gu;
    for (const match of source.matchAll(indirectCall))
      if (functionAliases.has(match[1] ?? '')) return true;
  }

  if (functionAliases.size) {
    const call = /\b([A-Za-z_$][\w$]*)\s*\(/gu;
    for (const match of source.matchAll(call))
      if (functionAliases.has(match[1] ?? '')) return true;
  }
  if (namespaceAliases.size) {
    const reflectiveMember =
      /\bReflect\s*\.\s*(?:apply|construct)\s*\(\s*([A-Za-z_$][\w$]*)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*,/gu;
    for (const match of source.matchAll(reflectiveMember))
      if (namespaceAliases.has(match[1] ?? '')) return true;
  }
  if (namespaceAliases.size) {
    const memberCall =
      /\b([A-Za-z_$][\w$]*)\s*\.\s*(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/gu;
    for (const match of source.matchAll(memberCall))
      if (namespaceAliases.has(match[1] ?? '')) return true;
    const computedMemberCall =
      /\b([A-Za-z_$][\w$]*)\s*\[[^\]\n]{1,128}\]\s*\(/gu;
    for (const match of source.matchAll(computedMemberCall))
      if (namespaceAliases.has(match[1] ?? '')) return true;
  }
  const directRequireCall =
    /\brequire\(\s*(['"])(?:node:)?child_process\1\s*\)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/u;
  if (directRequireCall.test(source)) return true;
  return false;
}

/** Resolves literal relative targets from recognized child_process namespaces. */
function staticChildProcessTargets(source: string): string[] {
  const namespaceAliases = new Set<string>();
  const functionAliases = new Map<string, Set<string>>();
  const namespaceRequire =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*(['"])(?:node:)?child_process\2\s*\)/gu;
  const namespaceImport =
    /\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*(['"])(?:node:)?child_process\2/gu;
  const destructuredRequire =
    /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*(['"])(?:node:)?child_process\2\s*\)/gu;
  const namedImport =
    /\bimport\s*\{([^}]*)\}\s*from\s*(['"])(?:node:)?child_process\2/gu;
  const namespaceFunctionAlias =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\.\s*(fork|spawn|spawnSync|execFile|execFileSync)\b/gu;
  const addFunctions = (list: string, esm: boolean): void => {
    for (const specifier of list.split(',')) {
      const parts = esm
        ? specifier.trim().split(/\s+as\s+/u)
        : specifier.trim().split(/\s*:\s*/u);
      const method = parts[0]?.trim();
      const local = parts[1]?.trim() ?? method;
      if (
        method &&
        local &&
        ['fork', 'spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(
          method
        )
      ) {
        const methods = functionAliases.get(local) ?? new Set<string>();
        methods.add(method);
        functionAliases.set(local, methods);
      }
    }
  };
  for (const match of source.matchAll(namespaceRequire))
    if (match[1]) namespaceAliases.add(match[1]);
  for (const match of source.matchAll(namespaceImport))
    if (match[1]) namespaceAliases.add(match[1]);
  for (const match of source.matchAll(destructuredRequire))
    if (match[1]) addFunctions(match[1], false);
  for (const match of source.matchAll(namedImport))
    if (match[1]) addFunctions(match[1], true);
  for (const match of source.matchAll(namespaceFunctionAlias)) {
    const local = match[1];
    const namespace = match[2];
    const method = match[3];
    if (local && namespace && method && namespaceAliases.has(namespace)) {
      const methods = functionAliases.get(local) ?? new Set<string>();
      methods.add(method);
      functionAliases.set(local, methods);
    }
  }

  const targets = new Set<string>();
  const record = (candidate: string | undefined): void => {
    if (candidate && targets.size < MAX_CACHED_REFERENCES_PER_CONTENT)
      targets.add(candidate);
  };
  const namespaceExecution =
    /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:spawn|execFile)(?:Sync)?\s*\(\s*(['"])(?:node|bash|sh|python3?|deno|bun)\2\s*,\s*\[\s*(['"])(\.{1,2}\/[^'"]+)\3/gu;
  for (const match of source.matchAll(namespaceExecution)) {
    if (namespaceAliases.has(match[1] ?? '')) record(match[4]);
    if (targets.size >= MAX_CACHED_REFERENCES_PER_CONTENT) break;
  }
  const namespaceFork =
    /\b([A-Za-z_$][\w$]*)\s*\.\s*fork\s*\(\s*(['"])(\.{1,2}\/[^'"]+)\2/gu;
  for (const match of source.matchAll(namespaceFork)) {
    if (namespaceAliases.has(match[1] ?? '')) record(match[3]);
    if (targets.size >= MAX_CACHED_REFERENCES_PER_CONTENT) break;
  }
  const functionExecution =
    /\b([A-Za-z_$][\w$]*)\s*\(\s*(['"])(?:node|bash|sh|python3?|deno|bun)\2\s*,\s*\[\s*(['"])(\.{1,2}\/[^'"]+)\3/gu;
  for (const match of source.matchAll(functionExecution)) {
    if (
      ['spawn', 'spawnSync', 'execFile', 'execFileSync'].some((method) =>
        functionAliases.get(match[1] ?? '')?.has(method)
      )
    )
      record(match[4]);
    if (targets.size >= MAX_CACHED_REFERENCES_PER_CONTENT) break;
  }
  const functionFork =
    /\b([A-Za-z_$][\w$]*)\s*\(\s*(['"])(\.{1,2}\/[^'"]+)\2/gu;
  for (const match of source.matchAll(functionFork)) {
    if (functionAliases.get(match[1] ?? '')?.has('fork')) record(match[3]);
    if (targets.size >= MAX_CACHED_REFERENCES_PER_CONTENT) break;
  }
  const reflectiveExecution =
    /\bReflect\s*\.\s*apply\s*\(\s*(?:([A-Za-z_$][\w$]*)\s*\.\s*(spawn|execFile)(?:Sync)?|([A-Za-z_$][\w$]*))\s*,[\s\S]{0,256}?\[\s*(['"])(?:node|bash|sh|python3?|deno|bun)\4\s*,\s*\[\s*(['"])(\.{1,2}\/[^'"]+)\5/gu;
  for (const match of source.matchAll(reflectiveExecution)) {
    const namespace = match[1];
    const method = match[2];
    const alias = match[3];
    const recognizedNamespaceMethod =
      namespace !== undefined &&
      namespaceAliases.has(namespace) &&
      method !== undefined;
    const recognizedFunctionAlias =
      alias !== undefined &&
      ['spawn', 'spawnSync', 'execFile', 'execFileSync'].some((candidate) =>
        functionAliases.get(alias)?.has(candidate)
      );
    if (recognizedNamespaceMethod || recognizedFunctionAlias) record(match[6]);
    if (targets.size >= MAX_CACHED_REFERENCES_PER_CONTENT) break;
  }
  const applyExecution =
    /\b(?:(?:([A-Za-z_$][\w$]*)\s*\.\s*(spawn|execFile)(?:Sync)?)|([A-Za-z_$][\w$]*))\s*\.\s*apply\s*\(\s*[^,)]{0,128}\s*,[\s\S]{0,128}?\[\s*(['"])(?:node|bash|sh|python3?|deno|bun)\4\s*,\s*\[\s*(['"])(\.{1,2}\/[^'"]+)\5/gu;
  const callExecution =
    /\b(?:(?:([A-Za-z_$][\w$]*)\s*\.\s*(spawn|execFile)(?:Sync)?)|([A-Za-z_$][\w$]*))\s*\.\s*call\s*\(\s*[^,)]{0,128}\s*,\s*(['"])(?:node|bash|sh|python3?|deno|bun)\4\s*,\s*\[\s*(['"])(\.{1,2}\/[^'"]+)\5/gu;
  if (namespaceAliases.size || functionAliases.size) {
    for (const pattern of [applyExecution, callExecution]) {
      for (const match of source.matchAll(pattern)) {
        const namespace = match[1];
        const method = match[2];
        const alias = match[3];
        const recognizedNamespaceMethod =
          namespace !== undefined &&
          namespaceAliases.has(namespace) &&
          method !== undefined;
        const recognizedFunctionAlias =
          alias !== undefined &&
          ['spawn', 'spawnSync', 'execFile', 'execFileSync'].some((candidate) =>
            functionAliases.get(alias)?.has(candidate)
          );
        if (recognizedNamespaceMethod || recognizedFunctionAlias)
          record(match[6]);
        if (targets.size >= MAX_CACHED_REFERENCES_PER_CONTENT) break;
      }
      if (targets.size >= MAX_CACHED_REFERENCES_PER_CONTENT) break;
    }
  }
  return [...targets].sort();
}

/** Resolves literal relative PowerShell Start-Process targets without execution. */
function staticPowerShellTargets(source: string): string[] {
  if (!/\bStart-Process\b/iu.test(source)) return [];
  const targets = new Set<string>();
  const startProcessTarget =
    /\bStart-Process\s+(?:-FilePath\s+)?(?:"(\.{1,2}[\\/][^"'\r\n;&|]{1,256})"|'(\.{1,2}[\\/][^"'\r\n;&|]{1,256})'|(\.{1,2}[\\/][^\s;&|]+))/giu;
  for (const match of source.matchAll(startProcessTarget)) {
    const target = match[1] ?? match[2] ?? match[3];
    if (target && targets.size < MAX_CACHED_REFERENCES_PER_CONTENT)
      targets.add(target.replaceAll('\\', '/'));
    if (targets.size >= MAX_CACHED_REFERENCES_PER_CONTENT) break;
  }
  return [...targets].sort();
}
const automaticScript =
  /\b(?:curl|wget)\b[^\n;&]{0,180}(?:\||;|&&)\s*(?:sh|bash)/iu;
// Creation and archive listing do not constitute unpack-and-execute.
const archiveExtraction =
  /\b(?:tar\s+(?:--extract\b|--get\b|-?[a-z]*x[a-z]*\b)|bsdtar\s+(?:--extract\b|-?[a-z]*x[a-z]*\b)|cpio\s+(?:--extract\b|-(?![a-z]*t)[a-z]*i[a-z]*\b)|(?:busybox\s+)?unzip\s+(?!-[lt]\b)|7z(?:a|r|z)?\s+(?:x|e)\b|(?:unrar|rar)\s+(?:x|e)\b|jar\s+(?:x[a-z]*\b|--extract\b)|Expand-Archive\b|python(?:3)?\s+-m\s+(?:zipfile|tarfile)\s+-e\b)/giu;
const archiveExecutionTarget =
  /(?:\bStart-Process\b(?:\s+-FilePath)?\s+[^\s;&|]+|\b(?:node(?:\.exe)?|bash|sh|zsh|pwsh|powershell|python(?:3)?|java(?:\.exe)?|deno|bun|ruby|perl|php|cmd(?:\.exe)?)\b\s+(?:-jar\s+|\/(?:c|k)\s+)?[^\s;&|]+|(?:^|[;&|]\s*)(?:call\s+)?(?:&\s*)?\.{1,2}[\\/]\S+)/imu;
const archiveApiExtraction =
  /\b(?:new\s+AdmZip\s*\([^)]{0,1024}\)\s*\.\s*extractAllTo\s*\(|(?:(?:zipfile\.)?ZipFile|(?:tarfile\.)?TarFile|tarfile\.open)\s*\([\s\S]{0,1024}?\.\s*extract(?:all)?\s*\(|(?:tar|tarModule)\s*\.\s*(?:x|extract)\s*\(|shutil\.unpack_archive\s*\(|unzipper\s*\.\s*Extract\s*\(|extractZip\s*\(|decompress\s*\(|(?:zip|zipFile)\s*\.\s*extract\s*\()/giu;
const archiveApiExecution =
  /\b(?:subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system|ProcessBuilder|Runtime\.getRuntime\s*\(\)\s*\.\s*exec|(?:child_process\.)?(?:exec|execFile|spawn|fork)|(?:new\s+)?Deno\.Command)\s*\(/u;
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

function archiveExtractionPresent(source: string): boolean {
  archiveExtraction.lastIndex = 0;
  if (archiveExtraction.test(source)) return true;
  archiveApiExtraction.lastIndex = 0;
  return archiveApiExtraction.test(source);
}

function archiveLaunchPresent(source: string): boolean {
  // Starting an extractor with "node ./unpack.js" is NOT proof that the
  // extracted file is subsequently executed. Require a programmatic process
  // invocation or an explicit shell execution of a local relative target.
  // The target may still be unrelated to the archive; report it as unknown.
  return (
    archiveApiExecution.test(source) ||
    /(?:^|[;\n]&?\s*|&&\s*|\|\|\s*)(?:exec\s+|&\s+)?\.{1,2}[\\/]\S+/mu.test(
      source
    )
  );
}

function hasArchiveExecution(source: string): boolean {
  archiveExtraction.lastIndex = 0;
  for (const match of source.matchAll(archiveExtraction)) {
    const after = source
      .slice((match.index ?? 0) + match[0].length)
      .slice(0, 1024);
    const separator = after.search(/(?:&&|;|\|\||\r?\n)/u);
    if (
      separator >= 0 &&
      archiveExecutionTarget.test(after.slice(separator + 1))
    )
      return true;
  }
  archiveApiExtraction.lastIndex = 0;
  for (const match of source.matchAll(archiveApiExtraction)) {
    const after = source
      .slice((match.index ?? 0) + match[0].length)
      .slice(0, 2048);
    if (archiveApiExecution.test(after)) return true;
  }
  return false;
}

/** Returns behavior labels without retaining or reporting matching source text. */
function behaviorSignals(source: string): string[] {
  const signals: string[] = [];
  if (suspiciousPayload.test(source) || encodedInterpreterLoader.test(source))
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
function staticShellTargets(source: string): {
  targets: string[];
  unresolvedShellCommand: boolean;
} {
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
  let unresolvedShellCommand = false;
  // `eval` executes command text and a variable passed to `exec` selects a
  // runtime target. Neither is resolved by this static path-only model.
  const dynamicExecutionPattern =
    /\beval\s+(?:"[^"\n]*"|'[^'\n]*'|[^\s;&|]+)|\bexec\s+(?:"\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)"|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)/gmu;
  if (dynamicExecutionPattern.test(source)) unresolvedShellCommand = true;
  const executionPattern =
    /\b(?:node(?:\.exe)?|bash|sh|zsh|python(?:3)?|ruby|perl|php|bun)(?:\.exe)?\s+(?:"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*))(?=\s|[;&|]|$)/gmu;
  for (const match of source.matchAll(executionPattern)) {
    const name = match[1] ?? match[2] ?? match[3] ?? match[4];
    if (!name) continue;
    const target = resolveTarget(name, match.index ?? 0, new Set(), 0);
    if (target) targets.add(target);
  }
  // Resolve only an exact variable alias supplied to a shell -c wrapper.
  // Command strings, interpolation and shell evaluation remain out of scope.
  const shellCommandPattern =
    /\b(?:bash|sh|zsh)(?:\.exe)?\s+-c\s+(?:"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*))(?=\s|[;&|]|$)/gmu;
  for (const match of source.matchAll(shellCommandPattern)) {
    const name = match[1] ?? match[2] ?? match[3] ?? match[4];
    if (!name) continue;
    const target = resolveTarget(name, match.index ?? 0, new Set(), 0);
    if (target) targets.add(target);
    else unresolvedShellCommand = true;
  }
  return { targets: [...targets].sort(), unresolvedShellCommand };
}

/** Reuses source-derived signals and path-neutral references by exact content hash. */
function contentAnalysis(source: string): Readonly<{
  references?: readonly string[];
  signals: readonly string[];
  unresolvedShellCommand: boolean;
  dynamicExecution: boolean;
  archiveExtracts: boolean;
  archiveLaunches: boolean;
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
  const shellAnalysis = staticShellTargets(source);
  for (const target of shellAnalysis.targets) references.add(target);
  for (const target of staticChildProcessTargets(source))
    references.add(target);
  for (const target of staticPowerShellTargets(source)) references.add(target);
  const result = Object.freeze({
    ...(references.size <= MAX_CACHED_REFERENCES_PER_CONTENT
      ? { references: Object.freeze([...references].sort()) }
      : {}),
    signals: Object.freeze(behaviorSignals(source)),
    unresolvedShellCommand: shellAnalysis.unresolvedShellCommand,
    dynamicExecution: hasDynamicExecution(source),
    archiveExtracts: archiveExtractionPresent(source),
    archiveLaunches: archiveLaunchPresent(source)
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

function addPackageScriptReferences(
  source: string,
  fromManifest: string,
  packageNameManifests: ReadonlyMap<string, string | undefined>,
  manifests: ReadonlySet<string>,
  references: Set<string>,
  addReference: (references: Set<string>, reference: string) => void
): void {
  workspaceScriptReference.lastIndex = 0;
  let unqualifiedSource = source;
  for (const match of source.matchAll(workspaceScriptReference)) {
    const rawSelector = match[1] ?? match[4] ?? match[5] ?? match[7] ?? '';
    const selector =
      rawSelector.length > 1 &&
      rawSelector[0] === rawSelector.at(-1) &&
      (rawSelector[0] === '"' || rawSelector[0] === "'")
        ? rawSelector.slice(1, -1)
        : rawSelector;
    const scriptName = match[2] ?? match[3] ?? match[6] ?? match[8] ?? '';
    const namedManifest = packageNameManifests.get(selector);
    let targetManifest = namedManifest;
    if (namedManifest === undefined && !packageNameManifests.has(selector)) {
      const target = path.posix.normalize(
        path.posix.join(path.posix.dirname(fromManifest), selector)
      );
      if (
        target !== '..' &&
        !target.startsWith('../') &&
        !path.posix.isAbsolute(selector)
      ) {
        const candidate = path.posix.join(target, 'package.json');
        if (manifests.has(candidate)) targetManifest = candidate;
      }
    }
    addReference(
      references,
      targetManifest && scriptName
        ? `npm-script:${targetManifest}\0${scriptName}`
        : `npm-script-unresolved:${selector}:${scriptName}`
    );
    const start = match.index ?? 0;
    unqualifiedSource =
      unqualifiedSource.slice(0, start) +
      ' '.repeat(match[0].length) +
      unqualifiedSource.slice(start + match[0].length);
  }
  packageScriptReference.lastIndex = 0;
  for (const match of unqualifiedSource.matchAll(packageScriptReference)) {
    const name = match[1] ?? match[2] ?? match[3] ?? '';
    addReference(references, `npm-script:${fromManifest}\0${name}`);
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
  scripts: ReadonlyMap<string, string>;
  packageNameManifests: ReadonlyMap<string, string | undefined>;
  manifests: ReadonlySet<string>;
} {
  const entries: Entry[] = [];
  const scriptContents = new Map<string, string>();
  const packageNameManifests = new Map<string, string | undefined>();
  const manifests = new Set<string>();
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
    for (const target of staticShellTargets(source).targets)
      addReference(references, target);
  };
  for (const file of files) {
    if (file.path !== 'package.json' && !file.path.endsWith('/package.json'))
      continue;
    manifests.add(file.path);
    const manifest = safeJson(file.content);
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest))
      continue;
    const packageName = (manifest as { name?: unknown }).name;
    if (typeof packageName === 'string' && packageName.length > 0)
      packageNameManifests.set(
        packageName,
        packageNameManifests.has(packageName) ? undefined : file.path
      );
  }
  for (const file of files) {
    if (file.path !== 'package.json' && !file.path.endsWith('/package.json'))
      continue;
    const manifest = safeJson(file.content);
    if (manifest && typeof manifest === 'object' && !Array.isArray(manifest)) {
      const scripts = (manifest as { scripts?: unknown }).scripts;
      if (scripts && typeof scripts === 'object' && !Array.isArray(scripts)) {
        for (const [name, value] of Object.entries(scripts)) {
          if (typeof value !== 'string') continue;
          const scriptKey = `${file.path}\0${name}`;
          scriptContents.set(scriptKey, value);
          const refs = new Set<string>();
          addExecutableReferences(value, refs);
          addPackageScriptReferences(
            value,
            file.path,
            packageNameManifests,
            manifests,
            refs,
            addReference
          );
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
            signals: contentAnalysis(value).signals,
            suspicious:
              contentAnalysis(value).signals.length > 0 ||
              automaticScript.test(value),
            unknown: hasDynamicExecution(value) && refs.size === 0
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
          if (object.type === 'npm' && typeof object.script === 'string')
            addReference(
              refs,
              `npm-script:${path.posix.join(
                path.posix.dirname(file.path),
                '..',
                'package.json'
              )}\0${object.script}`
            );
          if (automatic || refs.size || hasDynamicExecution(source))
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
              signals: contentAnalysis(source).signals,
              suspicious:
                contentAnalysis(source).signals.length > 0 ||
                automaticScript.test(source),
              unknown: hasDynamicExecution(source) && refs.size === 0
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
        hasDynamicExecution(file.content)
      )
        addEntry({
          file: file.path,
          referenceBase: file.path,
          kind: 'tool-config',
          automatic: true,
          references: refs,
          signals: contentAnalysis(file.content).signals,
          suspicious: contentAnalysis(file.content).signals.length > 0,
          unknown: hasDynamicExecution(file.content) && refs.size === 0
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
      signals: contentAnalysis(file.content).signals,
      suspicious:
        contentAnalysis(file.content).signals.length > 0 ||
        automaticScript.test(file.content),
      unknown: hasDynamicExecution(file.content) && refs.size === 0
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
          signals: contentAnalysis(value.run).signals,
          suspicious:
            contentAnalysis(value.run).signals.length > 0 ||
            automaticScript.test(value.run),
          unknown:
            dynamicCwd || (hasDynamicExecution(value.run) && refs.size === 0)
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
      signals,
      suspicious: signals.length > 0,
      unknown: hasDynamicExecution(file.content) && refs.size === 0
    });
  }
  return {
    entries,
    truncated,
    scripts: scriptContents,
    packageNameManifests,
    manifests
  };
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
    const traceHash = createHash('sha256')
      .update('toolip-malicious-trace-v2\0')
      .update(entry.file)
      .update('\0');
    let tracedPaths = 1;
    const recordTrace = (location: string): void => {
      traceHash.update(location).update('\0');
      tracedPaths++;
      if (trace.length < MAX_REPORTED_TRACE_PATHS) trace.push(location);
    };
    const preserveTraceEndpoint = (location: string): void => {
      if (trace.length >= MAX_REPORTED_TRACE_PATHS && !trace.includes(location))
        trace[trace.length - 1] = location;
    };
    const queue = [...entry.references].map(
      (reference) => [entry.referenceBase, reference] as const
    );
    const entryAnalysis = contentAnalysis(content.get(entry.file) ?? '');
    const signals = new Set([...entry.signals, ...entryAnalysis.signals]);
    let archiveExtracted = entryAnalysis.archiveExtracts;
    let archiveLaunched = entryAnalysis.archiveLaunches;
    let dynamicUnknown =
      entry.unknown ||
      entryAnalysis.unresolvedShellCommand ||
      signals.has('archive-extraction-and-execution');
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
      if (reference.startsWith('npm-script-unresolved:')) {
        dynamicUnknown = true;
        continue;
      }
      if (reference.startsWith('npm-script:')) {
        const [targetManifest, scriptName] = reference
          .slice('npm-script:'.length)
          .split('\0');
        if (!targetManifest || !scriptName) {
          dynamicUnknown = true;
          continue;
        }
        const targetText = entryResult.scripts.get(
          `${targetManifest}\0${scriptName}`
        );
        if (targetText === undefined) {
          dynamicUnknown = true;
          continue;
        }
        recordTrace(`${targetManifest}#scripts.${scriptName}`);
        const targetAnalysis = contentAnalysis(targetText);
        archiveExtracted ||= targetAnalysis.archiveExtracts;
        archiveLaunched ||= targetAnalysis.archiveLaunches;
        dynamicUnknown ||=
          targetAnalysis.dynamicExecution ||
          targetAnalysis.unresolvedShellCommand ||
          targetAnalysis.signals.includes('archive-extraction-and-execution');
        for (const signal of targetAnalysis.signals) signals.add(signal);
        if (
          targetAnalysis.signals.length > 0 ||
          automaticScript.test(targetText)
        ) {
          payload = true;
          preserveTraceEndpoint(`${targetManifest}#scripts.${scriptName}`);
        }
        for (const hookName of [`pre${scriptName}`, `post${scriptName}`]) {
          if (
            entryResult.scripts.has(`${targetManifest}\0${hookName}`) &&
            !enqueue(
              targetManifest,
              `npm-script:${targetManifest}\0${hookName}`
            )
          )
            break;
        }
        for (const nested of targetAnalysis.references ?? [])
          if (!enqueue(targetManifest, nested)) break;
        const nestedScripts = new Set<string>();
        addPackageScriptReferences(
          targetText,
          targetManifest,
          entryResult.packageNameManifests,
          entryResult.manifests,
          nestedScripts,
          (_references, nested) => nestedScripts.add(nested)
        );
        for (const nested of nestedScripts)
          if (!enqueue(targetManifest, nested)) break;
        continue;
      }
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
      recordTrace(target);
      const targetText = content.get(target) ?? '';
      const targetAnalysis = contentAnalysis(targetText);
      archiveExtracted ||= targetAnalysis.archiveExtracts;
      archiveLaunched ||= targetAnalysis.archiveLaunches;
      dynamicUnknown ||=
        targetAnalysis.dynamicExecution ||
        targetAnalysis.unresolvedShellCommand ||
        targetAnalysis.signals.includes('archive-extraction-and-execution');
      for (const signal of targetAnalysis.signals) signals.add(signal);
      if (
        targetAnalysis.signals.length > 0 ||
        automaticScript.test(targetText)
      ) {
        payload = true;
        preserveTraceEndpoint(target);
      }
      const nestedReferences = targetAnalysis.references;
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
        for (const nested of staticShellTargets(targetText).targets)
          if (!enqueue(target, nested)) break;
      }
    }
    // An extractor in one reachable script and an execution command in a
    // second file form a potential unpack-and-run chain. Without inspecting
    // the unpacked artifact, its exact runtime target is unknown: preserve
    // that uncertainty instead of presenting the trace as resolved.
    if (archiveExtracted && archiveLaunched) {
      signals.add('archive-extraction-and-execution');
      payload = true;
      dynamicUnknown = true;
    }
    // Unknown references stay review leads unless suspicious behavior is also
    // present. Automatic entrypoints or multi-file traces raise a positive
    // payload signal; automation alone is not a malicious-content indicator.
    const elevated = payload && (entry.automatic || tracedPaths > 1);
    if (!payload && !dynamicUnknown) continue;
    const confidence = elevated ? 'high' : 'low';
    const ruleId = payload ? 'TLP-MAL-001' : 'TLP-MAL-002';
    const traceDisplay = trace.map(safeDisplayPath);
    // Preserve existing stable finding IDs for ordinary traces. On a very
    // large graph, cap report metadata and derive its identity from the
    // complete path stream rather than sorting and retaining 100k strings.
    const traceId =
      tracedPaths > MAX_REPORTED_TRACE_PATHS
        ? stableId([ruleId, entry.file, entry.kind, traceHash.digest('hex')])
        : stableId([ruleId, entry.file, entry.kind, ...[...trace].sort()]);
    findings.push({
      id: traceId,
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
          summary: `Static trace: ${traceDisplay.slice(0, 20).join(' -> ')}${tracedPaths > 20 ? ' -> …' : ''}`
        }
      ],
      metadata: {
        entrypointKind: safeDisplayPath(entry.kind),
        automatic: entry.automatic,
        trace: traceDisplay,
        tracePathCount: tracedPaths,
        traceTruncated: tracedPaths > MAX_REPORTED_TRACE_PATHS,
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
  let binaryNamedTextProbes = 0;
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
    const binaryNamed = binaryExtensions.has(file.extension.toLowerCase());
    if (binaryNamed && ++binaryNamedTextProbes > MAX_BINARY_NAMED_TEXT_PROBES) {
      // Do not report a clean scan when a binary-looking name was never
      // inspected as text. A malicious script can carry a misleading suffix.
      skipped++;
      continue;
    }
    const result = await reader.read(file.absolutePath, signal, file.snapshot);
    if (result.status === 'binary') {
      if (binaryNamed) eligible--;
      else skipped++;
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
