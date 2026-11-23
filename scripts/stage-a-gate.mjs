#!/usr/bin/env node
/**
 * Trusted pre-execution scan of an exact Git tree.
 * This script must be run from the protected base workflow before any PR code
 * is installed, built, tested, or imported. It reads Git objects only.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  appendFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync, inflateRawSync } from 'node:zlib';
import { parse as parseToml } from 'smol-toml';
import {
  canonicalJsonSha256,
  parseCargoArtifactPolicy
} from './stage-a-canonical-json.mjs';
import { parseDocument } from '../vendor/stage-a-yaml-parser.mjs';
import { trustedScannerDigest } from './stage-a-scanner-digest.mjs';
import {
  parseStageAReviewedDependencyPolicy,
  applyStageAReviewedDependencyPolicy
} from './stage-a-reviewed-baseline.mjs';

const MAX_FILES = 100_000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_TREE_BYTES = 48 * 1024 * 1024;
const MAX_CAT_FILE_OUTPUT = MAX_TOTAL_BYTES + MAX_FILES * 128;
const MAX_GRAPH_EDGES = 200_000;
const MAX_TRACE_WORK = 1_000_000;
const MAX_TRACE_COUNT = 1_000;
const MAX_REFERENCED_BINARY_CANDIDATES = 256;
const MAX_REFERENCED_BINARY_GRAPH_DEPTH = 16;
const MAX_TRACE_BYTES = 1024 * 1024;
const MAX_ARTIFACT_COUNT = 500;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_ARTIFACT_UNPACKED_BYTES = 128 * 1024 * 1024;
const MAX_ARTIFACT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_ARTIFACT_FILES = 100_000;
const MAX_ARTIFACT_FILE_BYTES = 2 * 1024 * 1024;
const MAX_NPM_ARTIFACT_TEXT_FILE_BYTES = 32 * 1024 * 1024;
const MAX_ARTIFACT_CONCURRENCY = 4;
const MAX_ARTIFACT_DEADLINE_MS = 180_000;
const MAX_STAGE_A_EXCEPTION_BYTES = 256 * 1024;
const MAX_STAGE_A_EXCEPTION_COUNT = 500;
const MAX_OWNER_ATTESTATION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
// Owner attestations acknowledge bounded static-analysis uncertainty in archives
// whose exact bytes have already been integrity verified. They cannot authorize
// absent artifacts, failed checksums, malformed archives, or unsafe provenance.
const OWNER_ATTESTABLE_ARTIFACT_REASONS = new Set([
  'artifact-binary-content-uninspected',
  'dependency-lifecycle-script-review',
  'dynamic-command-resolution',
  'unresolved-child-process-execution',
  'unsupported-toolchain-execution',
  'unverified-npm-resolution'
]);
const MAX_STAGE_A_EXCEPTION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const REGEX_PREFIX_KEYWORDS = new Set([
  'await',
  'case',
  'delete',
  'do',
  'else',
  'in',
  'instanceof',
  'new',
  'of',
  'return',
  'throw',
  'typeof',
  'void',
  'yield'
]);
const BINARY_EXTENSIONS = new Set([
  '.7z',
  '.a',
  '.apk',
  '.avi',
  '.bin',
  '.class',
  '.db',
  '.dll',
  '.dylib',
  '.eot',
  '.exe',
  '.gif',
  '.gz',
  '.ico',
  '.jar',
  '.jpeg',
  '.jpg',
  '.mp3',
  '.mp4',
  '.o',
  '.pdf',
  '.png',
  '.rar',
  '.so',
  '.tar',
  '.tgz',
  '.ttf',
  '.wasm',
  '.webp',
  '.woff',
  '.woff2',
  '.zip'
]);
const ARCHIVE_EXTENSIONS = new Set([
  '.7z',
  '.apk',
  '.bz2',
  '.gz',
  '.jar',
  '.rar',
  '.tar',
  '.tgz',
  '.xz',
  '.zst',
  '.zip'
]);
const EXECUTABLE_BINARY_EXTENSIONS = new Set([
  '.a',
  '.apk',
  '.bin',
  '.class',
  '.dll',
  '.dylib',
  '.exe',
  '.jar',
  '.o',
  '.so',
  '.wasm'
]);
const TRUSTED_WORKFLOW_PATHS = new Set([
  '.github/CODEOWNERS',
  '.github/workflows/stage-a.yml',
  '.github/workflows/ci.yml',
  '.github/workflows/pr-quality.yml',
  '.github/workflows/codeql.yml',
  'scripts/stage-a-gate.mjs',
  'scripts/stage-a-npm-provenance.mjs',
  'scripts/stage-a-reviewed-baseline.mjs',
  'scripts/stage-a-scanner-digest.mjs',
  '.toolip/stage-a-reviewed-dependencies.json',

  'scripts/stage-a-yaml-entry.mjs',
  'scripts/STAGE-A-YAML-NOTICE.md',
  'vendor/stage-a-yaml-parser.mjs',
  'scripts/write-stage-a-artifact.mjs',
  'scripts/verify-stage-a-artifact.mjs',
  'scripts/verify-workflows.mjs',
  'scripts/verify-node.mjs'
]);
const candidatePath =
  /(?:^|\/)(?:package\.json|\.npmrc|\.pypirc|\.vscode\/tasks\.json|\.github\/workflows\/[^/]+\.ya?ml|\.husky\/[^/]+|Makefile|Dockerfile|[^/]+\.(?:[cm]?js|jsx|ts|tsx|mjs|cjs|sh|bash|ps1|json|ya?ml|toml|py|rb|go|rs|java|php|tf|gradle|kts))$/iu;
const dangerous = [
  /\beval\s*\(/u,
  /\bnew\s+Function\s*\(/u,
  /\b(?:curl|wget)\b[^\r\n;&|]{0,300}(?:\||&&|;)[ \t]*(?:sh|bash|zsh)\b/iu,
  /\b(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b/iu,
  /\b(?:pwsh|powershell)(?:\.exe)?\b[^\r\n]{0,128}\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/iu,
  /\b(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|[a-z_$][\w$]*)/u,
  /\b(?:exec|execSync|spawn|spawnSync)\s*\([^\r\n]{0,300}(?:(?:curl|wget)[^\r\n]{0,300}https?:\/\/|process\.env(?:\[['"])?\s*\.?\s*(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|GH_TOKEN|AZURE_CLIENT_SECRET))/iu,
  /\b(?:Invoke-Expression|IEX)\b[^\r\n]{0,300}(?:DownloadString|FromBase64String|https?:\/\/)/iu,
  /\b(?:base64\s+-d|openssl\s+enc)[^\r\n]{0,200}(?:\||;|&&)[ \t]*(?:sh|bash|node)\b/iu
];
const unsupportedToolchainCommand =
  /\b(?:cargo|rustc|go|python(?:3(?:\.\d+)?)?|pip(?:3(?:\.\d+)?)?|pipenv|pdm|rye|hatch|uv|poetry|conda|mamba|pixi|composer|mvnw?|gradlew?|dotnet|nuget|msbuild|java|javac|ruby|bundle|perl|pytest|tox|make|just|task|deno|pnpm|yarn|bun|docker|podman|corepack)\b[ \t]+\S/iu;
const unsupportedToolchainSpawn =
  /\b(?:spawn|spawnSync|execFile|execFileSync|execSync|exec|Command\.new|Command::new|exec\.Command|ProcessBuilder|subprocess\.(?:run|Popen|call)|os\.system|system|shell_exec|proc_open|popen)\s*\([\s\S]{0,160}?['"](?:cargo|rustc|go|python(?:3(?:\.\d+)?)?|pip(?:3(?:\.\d+)?)?|pipenv|pdm|rye|hatch|uv|poetry|conda|mamba|pixi|composer|mvnw?|gradlew?|dotnet|nuget|msbuild|java|javac|ruby|bundle|perl|pytest|tox|make|just|task|deno|npm(?:\.cmd)?|npx(?:\.cmd)?|pnpm|yarn|bun|docker|podman|corepack)['"]/iu;
const unsupportedToolchainShellCommand =
  /\b(?:exec|execSync|os\.system|system|shell_exec|proc_open|popen|subprocess\.(?:run|Popen|call))\s*\(\s*['"]\s*(?:cargo|rustc|go|python(?:3(?:\.\d+)?)?|pip(?:3(?:\.\d+)?)?|pipenv|pdm|rye|hatch|uv|poetry|conda|mamba|pixi|composer|mvnw?|gradlew?|dotnet|nuget|msbuild|java|javac|ruby|bundle|perl|pytest|tox|make|just|task|deno|npm(?:\.cmd)?|npx(?:\.cmd)?|pnpm|yarn|bun|docker|podman|corepack)\b/iu;
const npmResolutionSubcommands = new Set([
  'add',
  'create',
  'exec',
  'i',
  'install',
  'install-ci-test',
  'install-test',
  'link',
  'update',
  'upgrade',
  'x'
]);
const npmKnownReadOnlySubcommands = new Set([
  'audit',
  'cache',
  'config',
  'doctor',
  'fund',
  'help',
  'info',
  'pack',
  'ping',
  'prefix',
  'root',
  'run',
  'run-script',
  'start',
  'stop',
  'restart',
  'test',
  'version',
  'view',
  'whoami'
]);
const npmOptionValueFlags = new Set([
  '--cache',
  '--globalconfig',
  '--loglevel',
  '--prefix',
  '--registry',
  '--script-shell',
  '--userconfig',
  '--workspace',
  '-w'
]);
const npmBooleanFlags = new Set([
  '--audit',
  '--color',
  '--foreground-scripts',
  '--fund',
  '--global',
  '--ignore-scripts',
  '--no-audit',
  '--no-color',
  '--no-fund',
  '--no-progress',
  '--offline',
  '--prefer-offline',
  '--progress',
  '--workspaces'
]);
const npmExecutable = /(?:^|[\\/])?npm(?:\.cmd)?$/iu;
const npxExecutable = /(?:^|[\\/])?npx(?:\.cmd)?$/iu;
const untrustedWorkflowContext =
  /\bgithub\s*(?:\.\s*(?:event|head_ref|ref|ref_name|actor|triggering_actor|token|workflow|job|action)\b|\[\s*['"]?(?:event|head_ref|ref|ref_name|actor|triggering_actor|token|workflow|job|action)['"]?\s*\])|\b(?:inputs|secrets)\s*(?:\.|\[)|\b(?:steps|needs)\s*(?:\.\s*[A-Za-z_][\w-]*\s*\.\s*outputs\b|\[\s*['"][A-Za-z_][\w-]*['"]\s*\]\s*\.\s*outputs\b)|\bmatrix\s*(?:\.|\[)/iu;
const untrustedWorkflowEventContext =
  /\bgithub\s*(?:\.\s*(?:event|head_ref|ref|ref_name|actor|triggering_actor)\b|\[\s*['"]?(?:event|head_ref|ref|ref_name|actor|triggering_actor)['"]?\s*\])|\binputs\s*(?:\.|\[)/iu;
const untrustedWorkflowBracketContext =
  /\bgithub\s*\[\s*['"](?:event|head_ref|ref|ref_name|actor|triggering_actor|token|workflow|job|action)['"]\s*\]|\b(?:steps|needs)\s*\[\s*['"][A-Za-z_][\w-]*['"]\s*\]\s*\.\s*outputs\b/iu;
const untrustedWorkflowEventBracketContext =
  /\bgithub\s*\[\s*['"](?:event|head_ref|ref|ref_name|actor|triggering_actor)['"]\s*\]/iu;
const MAX_WORKFLOW_EXPRESSION_LENGTH = 4096;
const MAX_WORKFLOW_EXPRESSION_CACHE_ENTRIES = 10_000;
const MAX_WORKFLOW_EXPRESSION_SCAN_BYTES = 32 * 1024 * 1024;
const MAX_WORKFLOW_RUN_STEPS = 10_000;
const MAX_WORKFLOW_ENV_CHECKS = 100_000;

function hasUnsupportedToolchainExecution(source) {
  return (
    unsupportedToolchainCommand.test(source) ||
    unsupportedToolchainSpawn.test(source) ||
    unsupportedToolchainShellCommand.test(source)
  );
}

function hasUnresolvedChildProcessExecution(source) {
  const moduleName = /^(?:node:)?child_process$/u;
  const methods = new Set([
    'exec',
    'execSync',
    'execFile',
    'execFileSync',
    'spawn',
    'spawnSync',
    'fork'
  ]);
  const functionAliases = new Set();
  const namespaceAliases = new Set();
  const namedImport = /\bimport\s*\{([^}]*)\}\s*from\s*(['"])([^'"]+)\2/gu;
  for (const match of source.matchAll(namedImport)) {
    if (!moduleName.test(match[3] ?? '')) continue;
    for (const specifier of (match[1] ?? '').split(',')) {
      const [imported, local] = specifier.trim().split(/\s+as\s+/u);
      if (methods.has(imported ?? '')) functionAliases.add(local ?? imported);
    }
  }
  const cjsDestructure =
    /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*(['"])([^'"]+)\2\s*\)/gu;
  for (const match of source.matchAll(cjsDestructure)) {
    if (!moduleName.test(match[3] ?? '')) continue;
    for (const specifier of (match[1] ?? '').split(',')) {
      const [imported, local] = specifier.trim().split(/\s*:\s*/u);
      if (methods.has(imported ?? '')) functionAliases.add(local ?? imported);
    }
  }
  const dynamicImportDestructure =
    /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?import\(\s*(['"])([^'"]+)\2\s*\)/gu;
  for (const match of source.matchAll(dynamicImportDestructure)) {
    if (!moduleName.test(match[3] ?? '')) continue;
    for (const specifier of (match[1] ?? '').split(',')) {
      const [imported, local] = specifier.trim().split(/\s*:\s*/u);
      if (methods.has(imported ?? '')) functionAliases.add(local ?? imported);
    }
  }
  const namespaceBindings = [
    /\bimport\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s+from\s*(['"])([^'"]+)\2/gu,
    /\bimport\s+([A-Za-z_$][\w$]*)\s+from\s*(['"])([^'"]+)\2/gu,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*(['"])([^'"]+)\2\s*\)/gu,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?import\(\s*(['"])([^'"]+)\2\s*\)/gu
  ];
  for (const pattern of namespaceBindings)
    for (const match of source.matchAll(pattern))
      if (moduleName.test(match[3] ?? '') && match[1])
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
    const reflectiveCalls =
      /\bReflect\s*\.\s*(?:apply|construct)\s*\(\s*([A-Za-z_$][\w$]*)\s*,/gu;
    for (const match of source.matchAll(reflectiveCalls))
      if (functionAliases.has(match[1] ?? '')) return true;
    const indirectCalls = /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:apply|call)\s*\(/gu;
    for (const match of source.matchAll(indirectCalls))
      if (functionAliases.has(match[1] ?? '')) return true;
  }
  if (namespaceAliases.size) {
    const reflectiveMembers =
      /\bReflect\s*\.\s*(?:apply|construct)\s*\(\s*([A-Za-z_$][\w$]*)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*,/gu;
    for (const match of source.matchAll(reflectiveMembers))
      if (namespaceAliases.has(match[1] ?? '')) return true;
  }
  if (functionAliases.size) {
    const calls = /\b([A-Za-z_$][\w$]*)\s*\(/gu;
    for (const match of source.matchAll(calls))
      if (functionAliases.has(match[1] ?? '')) return true;
  }
  if (namespaceAliases.size) {
    const members =
      /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/gu;
    for (const match of source.matchAll(members))
      if (namespaceAliases.has(match[1] ?? '')) return true;
    const computedMembers = /\b([A-Za-z_$][\w$]*)\s*\[[^\]\n]{1,128}\]\s*\(/gu;
    for (const match of source.matchAll(computedMembers))
      if (namespaceAliases.has(match[1] ?? '')) return true;
  }
  return /\brequire\(\s*(['"])(?:node:)?child_process\1\s*\)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/u.test(
    source
  );
}

function hasDynamicShellCommandResolution(source) {
  return (
    /\balias\s+[^\s=]+\s*=/iu.test(source) ||
    /(?:^|[;\n])\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*\{/u.test(
      source
    ) ||
    /\b(?:export\s+)?PATH\s*=/u.test(source) ||
    /(?:^|[;&|])\s*(?:env|sudo|command|exec|nohup|time)\s+(?:(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|]+)\s+)*(?:"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"?|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\([^)]+\)|`[^`]+`)\s+/mu.test(
      source
    ) ||
    /(?:^|[;&|])\s*(?:source|\.)\s+(?:"?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"?|\$\([^)]+\)|`[^`]+`)/mu.test(
      source
    ) ||
    /\b(?:sh|bash|zsh|pwsh|powershell|cmd(?:\.exe)?)\s+(?:-[A-Za-z]+|\/[ck])\s+["']?\$(?:\{?[A-Za-z_][A-Za-z0-9_]*\}?|\()/iu.test(
      source
    ) ||
    /(?:^|[;&|])\s*(?:(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|[^\s;&|]+)\s*)*)(?:"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"?|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\([^)]+\)|`[^`]+`)\s+/mu.test(
      source
    )
  );
}

function hasUnsafeNpmConfigEnvironment(environment) {
  return Object.entries(environment).some(([name, value]) => {
    const normalizedName = name.toLowerCase();
    if (!normalizedName.startsWith('npm_config_')) return false;
    if (normalizedName === 'npm_config_registry')
      return value !== 'https://registry.npmjs.org/';
    if (
      normalizedName === 'npm_config_userconfig' ||
      normalizedName === 'npm_config_globalconfig'
    )
      return value !== '/dev/null';
    if (normalizedName === 'npm_config_cache') return false;
    if (normalizedName === 'npm_config_ignore_scripts')
      return !/^(?:true|1)$/iu.test(value);
    return true;
  });
}

function inspectWorkflowExpressions(source) {
  let offset = 0;
  let untrusted = false;
  let eventDerived = false;
  while (true) {
    const start = source.indexOf('${{', offset);
    if (start < 0) return { untrusted, eventDerived, malformed: false };
    let cursor = start + 3;
    let quoted = false;
    let closed = false;
    let expression = '';
    let rawExpression = '';
    while (
      cursor < source.length &&
      cursor - start <= MAX_WORKFLOW_EXPRESSION_LENGTH
    ) {
      const current = source[cursor] ?? '';
      const next = source[cursor + 1] ?? '';
      if (quoted) {
        if (current === "'" && next === "'") {
          expression += '  ';
          rawExpression += "''";
          cursor += 2;
        } else if (current === "'") {
          quoted = false;
          expression += ' ';
          rawExpression += current;
          cursor++;
        } else {
          expression += ' ';
          rawExpression += current;
          cursor++;
        }
        continue;
      }
      if (current === "'") {
        quoted = true;
        expression += ' ';
        rawExpression += current;
        cursor++;
      } else if (current === '}' && next === '}') {
        closed = true;
        break;
      } else {
        expression += current;
        rawExpression += current;
        cursor++;
      }
    }
    if (!closed)
      return { untrusted: true, eventDerived: true, malformed: true };
    if (
      untrustedWorkflowContext.test(expression) ||
      untrustedWorkflowBracketContext.test(rawExpression)
    )
      untrusted = true;
    if (
      untrustedWorkflowEventContext.test(expression) ||
      untrustedWorkflowEventBracketContext.test(rawExpression)
    )
      eventDerived = true;
    offset = cursor + 2;
  }
}

function commandMayLaunchChildProcess(command) {
  return /\b(?:node(?:js)?|npm|npx|pnpm|yarn|bun|python(?:3(?:\.\d+)?)?|pip(?:3(?:\.\d+)?)?|uv|poetry|composer|ruby|bundle|perl|pytest|tox|make|just|task|cargo|rustc|go|mvnw?|gradlew?|java|javac|docker|podman|corepack|sh|bash|zsh|pwsh|powershell|cmd(?:\.exe)?|source|exec|env|xargs|git|gh|curl|wget|tar|unzip|zip|ssh|scp|rsync|jq|awk|sed|grep|find|cat|head|tail|kubectl|helm|terraform|tofu|cmake|gcc|clang)\b|(?:^|[;&|]\s*)\.\.?\/[^\s;&|]+/iu.test(
    command
  );
}

function npmCommands(command) {
  const result = [];
  const matcher = /(?:^|[\s;&|])((?:[^\s;&|]*[\\/])?npm(?:\.cmd)?)(?=\s|$)/giu;
  let match;
  while (true) {
    match = matcher.exec(command);
    if (!match) break;
    const executable = match[1] ?? '';
    if (!npmExecutable.test(executable)) continue;
    const afterExecutable = matcher.lastIndex;
    const separator = command.slice(afterExecutable).search(/[;&|]/u);
    const rawArgs = command
      .slice(
        afterExecutable,
        separator < 0 ? command.length : afterExecutable + separator
      )
      .trim();
    const tokens =
      rawArgs.match(/"(?:\\.|[^"\\])*"|'(?:''|[^'])*'|[^\s]+/gu) ?? [];
    const args = tokens.map((token) =>
      token
        .replace(/^"([\s\S]*)"$/u, '$1')
        .replace(/^'((?:''|[\s\S])*)'$/u, '$1')
        .replaceAll("''", "'")
        .replace(/\\(.)/gu, '$1')
    );
    const options = new Map();
    let subcommand;
    let index = 0;
    while (index < args.length) {
      const token = args[index] ?? '';
      if (!token.startsWith('-')) {
        subcommand = token.toLowerCase();
        index++;
        break;
      }
      const equals = token.indexOf('=');
      const flag = equals < 0 ? token : token.slice(0, equals);
      if (equals >= 0) {
        options.set(flag, token.slice(equals + 1));
        index++;
      } else if (npmOptionValueFlags.has(flag)) {
        if (index + 1 >= args.length) return [...result, { malformed: true }];
        options.set(flag, args[index + 1] ?? '');
        index += 2;
      } else if (npmBooleanFlags.has(flag)) {
        options.set(flag, true);
        index++;
      } else {
        return [...result, { malformed: true }];
      }
    }
    if (subcommand === 'ci' || subcommand === 'clean-install') {
      while (index < args.length) {
        const token = args[index] ?? '';
        if (!token.startsWith('-')) {
          options.set('__unexpected_argument__', true);
          index++;
          continue;
        }
        const equals = token.indexOf('=');
        const flag = equals < 0 ? token : token.slice(0, equals);
        if (equals >= 0) {
          options.set(flag, token.slice(equals + 1));
          index++;
        } else if (npmOptionValueFlags.has(flag)) {
          if (index + 1 >= args.length) return [...result, { malformed: true }];
          options.set(flag, args[index + 1] ?? '');
          index += 2;
        } else {
          options.set(flag, true);
          index++;
        }
      }
    }
    result.push({ subcommand, options, args: args.slice(index) });
  }
  const npxMatcher =
    /(?:^|[\s;&|])((?:[^\s;&|]*[\\/])?npx(?:\.cmd)?)(?=\s|$)/giu;
  while (true) {
    match = npxMatcher.exec(command);
    if (!match) break;
    if (npxExecutable.test(match[1] ?? '')) result.push({ subcommand: 'npx' });
  }
  return result;
}

function requiresUnverifiedNpmResolution(
  command,
  { cwd = '.', allowRootCi = false } = {}
) {
  if (/\bNPM_CONFIG_[A-Z0-9_]+\s*=/iu.test(command)) return true;
  const invocations = npmCommands(command);
  if (invocations.some((invocation) => invocation.malformed)) return true;
  const normalizedCwd = path.posix.normalize(cwd.replaceAll('\\', '/'));
  const allowedCiFlags = new Set([
    '--globalconfig',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    '--no-progress',
    '--offline',
    '--prefer-offline',
    '--registry',
    '--userconfig'
  ]);
  for (const invocation of invocations) {
    const { subcommand, options } = invocation;
    if (!subcommand) return true;
    if (subcommand === 'npx' || npmResolutionSubcommands.has(subcommand))
      return true;
    if (subcommand === 'init' && invocation.args.length > 0) return true;
    if (subcommand === 'ci' || subcommand === 'clean-install') {
      if (
        !allowRootCi ||
        normalizedCwd !== '.' ||
        options.get('--ignore-scripts') !== true ||
        /\b(?:cd|pushd|popd)\b/iu.test(command) ||
        [...options.keys()].some((flag) => !allowedCiFlags.has(flag))
      )
        return true;
      for (const [flag, value] of options) {
        if (
          (flag === '--registry' && value !== 'https://registry.npmjs.org/') ||
          ((flag === '--userconfig' || flag === '--globalconfig') &&
            value !== '/dev/null')
        )
          return true;
      }
      continue;
    }
    if (!npmKnownReadOnlySubcommands.has(subcommand)) return true;
  }
  return false;
}
const suspiciousProcessExecution =
  /\b(?:exec|execSync|spawn|spawnSync)\s*\([^\r\n)]{0,300}(?:curl|wget|https?:\/\/|atob|fromBase64)/iu;
const credentialStoreProbe =
  /(?:keytar\.(?:getPassword|findPassword)|(?:security\s+find-(?:generic|internet)-password)|secret-tool\s+lookup|(?:cmdkey|vaultcmd)\s+\/list|(?:readFileSync|readFile|openSync|Get-Content|cat|type)\s*\([^\n)]{0,300}(?:\.aws[\\/]credentials|\.npmrc|\.docker[\\/]config\.json|\.ssh[\\/](?:id_rsa|id_ed25519)|Login Data|Local State)|process\.env(?:\[['"])?\s*\.?\s*(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|GH_TOKEN|AZURE_CLIENT_SECRET))/iu;
const outboundCredentialTransfer =
  /(?:\b(?:curl|wget|nc|ncat|socat)\b|\b(?:fetch|axios\.(?:post|put)|https?\.request)\s*\(|Invoke-WebRequest|upload(?:File|String))/iu;
const startupPersistence =
  /(?:\bcrontab\s+-|\b(?:systemctl|launchctl)\s+(?:enable|load|bootstrap)|\.config[\\/]autostart|(?:\.bashrc|\.zshrc|\.profile|Startup[\\/])|(?:CurrentVersion[\\/]Run|HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run))/iu;
// Creation and archive listing do not constitute unpack-and-execute.
const archiveExtraction =
  /\b(?:tar\s+(?:--extract\b|--get\b|-[vzf]{0,2}x[a-z]*\b|x[a-z]*\b)|bsdtar\s+(?:--extract\b|-[vzf]{0,2}x[a-z]*\b)|cpio\s+(?:--extract\b|-(?![a-z]*t)[a-z]*i[a-z]*\b)|(?:busybox\s+)?unzip\s+(?!-[lt]\b)|7z(?:a|r|z)?\s+(?:x|e)\b|(?:unrar|rar)\s+(?:x|e)\b|jar\s+(?:x[a-z]*\b|--extract\b)|Expand-Archive\b|python(?:3)?\s+-m\s+(?:zipfile|tarfile)\s+-e\b)/giu;
const archiveExecution =
  /(?:\bStart-Process\b(?:\s+-FilePath)?\s+[^\s;&|]+|\b(?:node(?:\.exe)?|bash|sh|zsh|pwsh|powershell|python(?:3)?|java(?:\.exe)?|deno|bun|ruby|perl|php|cmd(?:\.exe)?)\b\s+(?:-jar\s+|\/(?:c|k)\s+)?[^\s;&|]+|(?:^|[;&|\r\n]\s*)(?:call\s+)?(?:&\s*)?\.{1,2}[\\/]\S+)/imu;
const archiveApiExtraction =
  /\b(?:new\s+AdmZip\s*\([^)]{0,1024}\)\s*\.\s*extractAllTo\s*\(|(?:(?:zipfile\.)?ZipFile|(?:tarfile\.)?TarFile|tarfile\.open)\s*\([\s\S]{0,1024}?\.\s*extract(?:all)?\s*\(|(?:tar|tarModule)\s*\.\s*(?:x|extract)\s*\(|shutil\.unpack_archive\s*\(|unzipper\s*\.\s*Extract\s*\(|extractZip\s*\(|decompress\s*\(|(?:zip|zipFile)\s*\.\s*extract\s*\()/giu;
const archiveApiExecution =
  /\b(?:subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system|ProcessBuilder|Runtime\.getRuntime\s*\(\)\s*\.\s*exec|(?:child_process\.)?(?:exec|execFile|spawn|fork)|(?:new\s+)?Deno\.Command)\s*\(/u;

function hasArchiveExtractionAndExecution(source) {
  archiveExtraction.lastIndex = 0;
  for (const match of source.matchAll(archiveExtraction)) {
    const after = source
      .slice((match.index ?? 0) + match[0].length)
      .slice(0, 1024);
    const separator = after.search(/(?:&&|;|\|\||\r?\n)/u);
    if (separator >= 0 && archiveExecution.test(after.slice(separator + 1)))
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

function hasCredentialTransfer(source) {
  const probes = [...source.matchAll(new RegExp(credentialStoreProbe, 'giu'))];
  for (const probe of probes) {
    const start = Math.max(0, (probe.index ?? 0) - 1024);
    const end = Math.min(
      source.length,
      (probe.index ?? 0) + probe[0].length + 1024
    );
    if (outboundCredentialTransfer.test(source.slice(start, end))) return true;
  }
  return false;
}

export function maskJavaScriptNonCode(source, maskStrings = true) {
  const output = [...source];
  let quote = '';
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  let regexLiteral = false;
  let regexClass = false;
  let regexEscaped = false;
  let lastSignificant = '';
  let lastWord = '';
  let currentWord = '';
  const finishWord = () => {
    if (currentWord) lastWord = currentWord;
    currentWord = '';
  };
  const regexCanStart = () =>
    !lastSignificant ||
    '=([{,:;!&|?+-*%^~>'.includes(lastSignificant) ||
    REGEX_PREFIX_KEYWORDS.has(lastWord);
  for (let index = 0; index < source.length; index++) {
    const char = source[index] ?? '';
    const next = source[index + 1] ?? '';
    if (lineComment) {
      if (char === '\n') lineComment = false;
      else output[index] = ' ';
      continue;
    }
    if (blockComment) {
      output[index] = char === '\n' ? '\n' : ' ';
      if (char === '*' && next === '/') {
        output[index + 1] = ' ';
        index++;
        blockComment = false;
      }
      continue;
    }
    if (regexLiteral) {
      output[index] = char === '\n' ? '\n' : ' ';
      if (regexEscaped) regexEscaped = false;
      else if (char === '\\') regexEscaped = true;
      else if (char === '[') regexClass = true;
      else if (char === ']') regexClass = false;
      else if (char === '/' && !regexClass) {
        regexLiteral = false;
        finishWord();
        lastWord = 'value';
        lastSignificant = 'v';
        while (/[a-z]/iu.test(source[index + 1] ?? '')) {
          output[index + 1] = ' ';
          index++;
        }
      }
      continue;
    }
    if (quote) {
      if (maskStrings) output[index] = char === '\n' ? '\n' : ' ';
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === quote) {
        quote = '';
        finishWord();
        lastWord = 'value';
        lastSignificant = 'v';
      }
      continue;
    }
    if (char === '/' && next === '/') {
      lineComment = true;
      output[index] = output[index + 1] = ' ';
      index++;
    } else if (char === '/' && next === '*') {
      blockComment = true;
      output[index] = output[index + 1] = ' ';
      index++;
    } else if (char === '/' && regexCanStart()) {
      finishWord();
      regexLiteral = true;
      regexClass = false;
      regexEscaped = false;
      output[index] = ' ';
    } else if (char === '"' || char === "'" || char === '`') {
      finishWord();
      quote = char;
      if (maskStrings) output[index] = ' ';
    } else if (/[A-Za-z0-9_$]/u.test(char)) {
      currentWord += char;
      lastSignificant = char;
    } else {
      finishWord();
      if (!/\s/u.test(char)) lastSignificant = char;
    }
  }
  return output.join('');
}

function git(repo, args, maxBuffer = MAX_TREE_BYTES, input) {
  return execFileSync('git', ['--no-replace-objects', ...args], {
    cwd: repo,
    encoding: 'buffer',
    maxBuffer,
    timeout: 120_000,
    input,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_TERMINAL_PROMPT: '0',
      GIT_NO_REPLACE_OBJECTS: '1'
    }
  });
}

/** Fetch immutable blob objects using one bounded Git process. */
function catFileBatch(repo, oids) {
  if (oids.length === 0) return new Map();
  const output = git(
    repo,
    ['cat-file', '--batch'],
    MAX_CAT_FILE_OUTPUT,
    Buffer.from(`${oids.join('\n')}\n`)
  );
  const result = new Map();
  let offset = 0;
  for (const expectedOid of oids) {
    const endHeader = output.indexOf(10, offset);
    if (endHeader < 0) throw new Error('Git blob response header is truncated');
    const header = output.subarray(offset, endHeader).toString('ascii');
    const match = header.match(/^([0-9a-f]{40,64}) blob (\d+)$/u);
    if (!match || match[1] !== expectedOid)
      throw new Error('Git blob response does not match requested object');
    const size = Number(match[2]);
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_TOTAL_BYTES)
      throw new Error('Git blob response size exceeds the supported budget');
    const start = endHeader + 1;
    const end = start + size;
    if (end >= output.length || output[end] !== 10)
      throw new Error('Git blob response is truncated');
    result.set(expectedOid, output.subarray(start, end));
    offset = end + 1;
  }
  if (offset !== output.length)
    throw new Error('Git returned unexpected trailing blob data');
  return result;
}

function parseTree(raw) {
  if (raw.length > MAX_TREE_BYTES)
    throw new Error('Git tree exceeds Stage A output budget');
  let decoded;
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    throw new Error('Git tree contains a non-UTF-8 path');
  }
  const records = decoded.split('\0');
  if (records.at(-1) !== '') throw new Error('Git tree output is truncated');
  const blobs = [];
  const links = [];
  for (const record of records.slice(0, -1)) {
    const tab = record.indexOf('\t');
    if (tab < 0) throw new Error('Git tree record is malformed');
    const [mode, type, oid] = record.slice(0, tab).split(' ');
    const name = record.slice(tab + 1);
    if (type === 'commit' || mode === '160000')
      throw new Error(`Submodule requires review: ${name}`);
    if (type !== 'blob') continue;
    if (mode === '120000') {
      if (!/^[0-9a-f]{40,64}$/u.test(oid ?? ''))
        throw new Error(`Unsupported symlink blob: ${name}`);
      links.push({ path: name, oid, mode });
      continue;
    }
    if (
      !/^(?:100644|100755)$/u.test(mode ?? '') ||
      !/^[0-9a-f]{40,64}$/u.test(oid ?? '')
    )
      throw new Error(`Unsupported Git object mode: ${name}`);
    blobs.push({ path: name, oid, mode });
  }
  if (blobs.length + links.length > MAX_FILES)
    throw new Error('Git tree exceeds Stage A file-count budget');
  return { blobs, links };
}

function gitlinkSafePath(value) {
  return value.replaceAll('\\', '/');
}

function hasBlobPrefix(sortedPaths, prefix) {
  let low = 0;
  let high = sortedPaths.length;
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2);
    if ((sortedPaths[middle] ?? '') < prefix) low = middle + 1;
    else high = middle;
  }
  return (sortedPaths[low] ?? '').startsWith(prefix);
}

function pathsWithPrefix(sortedPaths, prefix) {
  let low = 0;
  let high = sortedPaths.length;
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2);
    if ((sortedPaths[middle] ?? '') < prefix) low = middle + 1;
    else high = middle;
  }
  const matches = [];
  while ((sortedPaths[low] ?? '').startsWith(prefix)) {
    matches.push(sortedPaths[low]);
    low++;
  }
  return matches;
}

function isTextCandidate(name) {
  if (
    candidatePath.test(name) ||
    path.posix.basename(name).lastIndexOf('.') <= 0
  )
    return true;
  return !BINARY_EXTENSIONS.has(path.posix.extname(name).toLowerCase());
}

function hasExecutableMagic(bytes) {
  return (
    bytes.subarray(0, 2).equals(Buffer.from([0x4d, 0x5a])) || // PE/COFF
    bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) || // ELF
    bytes.subarray(0, 4).equals(Buffer.from([0xca, 0xfe, 0xba, 0xbe])) || // JVM class
    bytes.subarray(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d])) || // WebAssembly
    bytes.subarray(0, 4).equals(Buffer.from([0xfe, 0xed, 0xfa, 0xce])) ||
    bytes.subarray(0, 4).equals(Buffer.from([0xce, 0xfa, 0xed, 0xfe])) ||
    bytes.subarray(0, 4).equals(Buffer.from([0xfe, 0xed, 0xfa, 0xcf])) ||
    bytes.subarray(0, 4).equals(Buffer.from([0xcf, 0xfa, 0xed, 0xfe])) ||
    bytes.subarray(0, 4).equals(Buffer.from([0xca, 0xfe, 0xba, 0xbf])) || // Mach-O/fat
    bytes.subarray(0, 2).equals(Buffer.from('#!'))
  );
}

function parseNameStatusDiff(raw) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    throw new Error('Git diff contains a non-UTF-8 path');
  }
  const fields = text.split('\0');
  if (fields.at(-1) !== '') throw new Error('Git diff output is truncated');
  const paths = new Set();
  for (let index = 0; index < fields.length - 1;) {
    const status = fields[index++];
    if (!/^(?:A|C\d*|D|M|R\d*|T|U|X|B)$/u.test(status ?? ''))
      throw new Error('Git diff contains an unsupported change status');
    const oldPath = fields[index++];
    if (typeof oldPath !== 'string' || !oldPath)
      throw new Error('Git diff contains a missing path');
    paths.add(oldPath);
    if (status.startsWith('R') || status.startsWith('C')) {
      const newPath = fields[index++];
      if (typeof newPath !== 'string' || !newPath)
        throw new Error('Git diff contains an incomplete rename/copy');
      paths.add(newPath);
    }
  }
  if (paths.size > MAX_FILES)
    throw new Error('Git diff exceeds file-count budget');
  return [...paths].sort();
}

function packageNameFromLocation(location) {
  const parts = location.split('/');
  let nodeModules = -1;
  for (let index = 0; index < parts.length; index++)
    if (parts[index] === 'node_modules') nodeModules = index;
  if (nodeModules < 0) return undefined;
  const first = parts[nodeModules + 1];
  if (!first) return undefined;
  if (first.startsWith('@')) {
    const second = parts[nodeModules + 2];
    return second ? `${first}/${second}` : undefined;
  }
  return first;
}

function validNpmPackageName(name) {
  return (
    typeof name === 'string' &&
    Buffer.byteLength(name) <= 214 &&
    /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/u.test(name)
  );
}

/** Enumerate exact base-to-head changes in O(F log F) time and O(F) space. */
export function listPullRequestChanges(repo, baseSha, headSha) {
  for (const sha of [baseSha, headSha])
    if (!/^[0-9a-f]{40}$/iu.test(sha ?? ''))
      throw new Error('Base and head commit SHAs are required');
  const raw = git(
    repo,
    [
      'diff',
      '--name-status',
      '-z',
      '-M',
      '-C',
      '-l1000',
      '--no-ext-diff',
      baseSha,
      headSha,
      '--'
    ],
    MAX_TREE_BYTES
  );
  return parseNameStatusDiff(raw);
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object')
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  return JSON.stringify(value);
}

export function parseNpmLockInventory(text) {
  let lock;
  try {
    lock = JSON.parse(text);
  } catch {
    throw new Error('npm lockfile is malformed JSON');
  }
  if (
    !lock ||
    ![2, 3].includes(lock.lockfileVersion) ||
    !lock.packages ||
    typeof lock.packages !== 'object' ||
    Array.isArray(lock.packages)
  )
    throw new Error('npm lockfile format is unsupported or incomplete');
  const artifacts = new Map();
  const records = new Map();
  const problems = [];
  for (const [location, item] of Object.entries(lock.packages)) {
    if (!location || item?.link === true) continue;
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      problems.push('invalid-lock-entry');
      continue;
    }
    if (typeof item.version !== 'string' || !item.version) {
      problems.push('unresolved-lock-entry');
      continue;
    }
    const resolved = item.resolved;
    const integrity = item.integrity;
    if (typeof resolved !== 'string' || typeof integrity !== 'string') {
      problems.push('missing-artifact-origin-or-integrity');
      continue;
    }
    let url;
    try {
      url = new URL(resolved);
    } catch {
      problems.push('unsupported-artifact-origin');
      continue;
    }
    if (
      url.protocol !== 'https:' ||
      url.hostname !== 'registry.npmjs.org' ||
      url.username ||
      url.password ||
      url.port ||
      url.search ||
      url.hash
    )
      problems.push('unsupported-artifact-origin');
    if (!/(?:^|\s)sha512-[A-Za-z0-9+/]+={0,2}(?=\s|$)/u.test(integrity))
      problems.push('missing-sha512-integrity');
    const installName = packageNameFromLocation(location);
    const name = item.name === undefined ? installName : item.name;
    if (!validNpmPackageName(name)) {
      problems.push(
        item.name === undefined
          ? 'unresolved-package-name'
          : 'invalid-registry-package-name'
      );
      continue;
    }
    artifacts.set(
      location,
      canonicalJson({
        name,
        version: item.version,
        resolved,
        integrity,
        hasInstallScript: item.hasInstallScript === true
      })
    );
    records.set(
      location,
      Object.freeze({
        location,
        name: name ?? '',
        version: item.version,
        resolved,
        integrity,
        hasInstallScript: item.hasInstallScript === true
      })
    );
  }
  return Object.freeze({
    artifacts,
    records,
    problems: Object.freeze([...new Set(problems)].sort()),
    rootDependencies: lock.packages[''] ?? {}
  });
}

export function compareNpmLockfiles(baseText, headText, manifestText) {
  if (!headText)
    return Object.freeze({
      changedArtifacts: 0,
      changedArtifactRecords: Object.freeze([]),
      artifactRecords: Object.freeze([]),
      artifactCount: 0,
      reasons: Object.freeze(['dependency-lock-missing'])
    });
  let base;
  let head;
  let manifest;
  try {
    base = baseText
      ? parseNpmLockInventory(baseText)
      : { artifacts: new Map() };
    head = parseNpmLockInventory(headText);
    manifest = JSON.parse(manifestText ?? '{}');
  } catch (error) {
    return Object.freeze({
      changedArtifacts: 0,
      changedArtifactRecords: Object.freeze([]),
      artifactRecords: Object.freeze([]),
      artifactCount: 0,
      reasons: Object.freeze([
        error instanceof Error ? error.message : 'invalid-dependency-metadata'
      ])
    });
  }
  const reasons = [...head.problems];
  const artifactRecords = [...head.records.values()].sort((left, right) =>
    left.location.localeCompare(right.location)
  );
  const groups = [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies'
  ];
  for (const group of groups) {
    if (
      canonicalJson(manifest[group] ?? {}) !==
      canonicalJson(head.rootDependencies[group] ?? {})
    )
      reasons.push('lockfile-manifest-mismatch');
  }
  let changedArtifacts = 0;
  const changedArtifactRecords = [];
  for (const [location, identity] of head.artifacts) {
    if (base.artifacts.get(location) !== identity) {
      changedArtifacts++;
      const record = head.records.get(location);
      if (record) changedArtifactRecords.push(record);
    }
  }
  if (changedArtifacts > 0) reasons.push('dependency-artifact-uninspected');
  return Object.freeze({
    changedArtifacts,
    changedArtifactRecords: Object.freeze(
      changedArtifactRecords.sort((left, right) =>
        left.location.localeCompare(right.location)
      )
    ),
    artifactRecords: Object.freeze(artifactRecords),
    artifactCount: head.artifacts.size,
    reasons: Object.freeze([...new Set(reasons)].sort())
  });
}

function readTarOctal(header, start, length) {
  const raw = header
    .subarray(start, start + length)
    .toString('ascii')
    .replace(/\0.*$/u, '')
    .trim();
  if (!raw) return 0;
  if (!/^[0-7]+$/u.test(raw)) throw new Error('tar-entry-size-invalid');
  const value = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value)) throw new Error('tar-entry-size-invalid');
  return value;
}

function readTarText(header, start, length) {
  const raw = header.subarray(start, start + length);
  const nul = raw.indexOf(0);
  return new TextDecoder('utf-8', { fatal: true }).decode(
    nul < 0 ? raw : raw.subarray(0, nul)
  );
}

function safeTarName(name) {
  if (
    !name ||
    name.startsWith('/') ||
    name.includes('\\') ||
    /^[A-Za-z]:/u.test(name)
  )
    throw new Error('tar-path-invalid');
  const parts = name.split('/').filter(Boolean);
  if (parts.some((part) => part === '.' || part === '..'))
    throw new Error('tar-path-invalid');
  const normalized = path.posix.normalize(name);
  if (normalized !== name.replace(/\/$/u, '') && normalized !== name)
    throw new Error('tar-path-invalid');
  return normalized;
}

/** Inspect an npm tarball without extracting or executing it. */
export function inspectNpmTarball(archive, artifact) {
  if (!Buffer.isBuffer(archive) || archive.length > MAX_ARTIFACT_BYTES)
    return Object.freeze({
      files: 0,
      bytes: 0,
      findings: Object.freeze([]),
      reasons: Object.freeze(['artifact-size-budget-exceeded']),
      hasInstallScript: false,
      binaryFiles: 0
    });
  let unpacked;
  try {
    unpacked = gunzipSync(archive, {
      maxOutputLength: MAX_ARTIFACT_UNPACKED_BYTES
    });
  } catch {
    return Object.freeze({
      files: 0,
      bytes: 0,
      findings: Object.freeze([]),
      reasons: Object.freeze(['artifact-gzip-invalid-or-over-budget']),
      hasInstallScript: false,
      binaryFiles: 0
    });
  }
  const reasons = [];
  const incompleteReasons = [];
  if (unpacked.length > 1024 * 1024 && unpacked.length > archive.length * 200)
    reasons.push('artifact-compression-ratio-exceeded');
  const findings = [];
  const seen = new Set();
  let offset = 0;
  let entries = 0;
  let files = 0;
  let bytes = 0;
  let binaryFiles = 0;
  let manifest;
  let packageRoot;
  let bindingGyp = false;
  let sawTerminator = false;
  while (offset + 512 <= unpacked.length) {
    const header = unpacked.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      sawTerminator = true;
      if (unpacked.subarray(offset).some((byte) => byte !== 0))
        reasons.push('tar-trailing-data');
      offset = unpacked.length;
      break;
    }
    let name;
    try {
      name = readTarText(header, 0, 100);
    } catch {
      reasons.push('tar-path-invalid');
      break;
    }
    const prefix = readTarText(header, 345, 155);
    if (prefix) name = `${prefix}/${name}`;
    let size;
    let canonical;
    try {
      size = readTarOctal(header, 124, 12);
      canonical = safeTarName(name);
      const entryRoot = canonical.split('/')[0];
      if (!entryRoot || (packageRoot && entryRoot !== packageRoot))
        throw new Error('tar-path-outside-package-root');
      if (!packageRoot) packageRoot = entryRoot;
      const declaredChecksum = readTarOctal(header, 148, 8);
      let checksum = 0;
      for (let index = 0; index < 512; index++)
        checksum += index >= 148 && index < 156 ? 32 : (header[index] ?? 0);
      if (checksum !== declaredChecksum)
        reasons.push('tar-header-checksum-invalid');
    } catch (error) {
      reasons.push(
        error instanceof Error ? error.message : 'tar-header-invalid'
      );
      break;
    }
    const type = String.fromCharCode(header[156] ?? 0);
    if (canonical === packageRoot && type !== '5') {
      reasons.push('tar-file-path-invalid');
      break;
    }
    const bodyStart = offset + 512;
    const bodyEnd = bodyStart + size;
    if (
      size > MAX_ARTIFACT_UNPACKED_BYTES ||
      bodyEnd > unpacked.length ||
      !Number.isSafeInteger(bodyEnd)
    ) {
      reasons.push('artifact-file-size-exceeded');
      break;
    }
    entries++;
    if (entries > MAX_ARTIFACT_FILES) {
      reasons.push('artifact-content-budget-exceeded');
      break;
    }
    if (['x', 'g', 'L', 'K', '1', '2', 'S'].includes(type)) {
      reasons.push('unsupported-tar-entry-type');
      break;
    }
    if (type === '0' || type === '\0' || type === '7') {
      if (canonical === packageRoot) {
        reasons.push('tar-file-path-invalid');
        break;
      }
      files++;
      bytes += size;
      if (files > MAX_ARTIFACT_FILES || bytes > MAX_ARTIFACT_UNPACKED_BYTES) {
        reasons.push('artifact-content-budget-exceeded');
        break;
      }
      if (seen.has(canonical)) {
        reasons.push('duplicate-tar-path');
        break;
      }
      seen.add(canonical);
      const content = unpacked.subarray(bodyStart, bodyEnd);
      if (canonical === `${packageRoot}/binding.gyp`) bindingGyp = true;
      if (canonical === `${packageRoot}/package.json`) {
        try {
          manifest = JSON.parse(
            new TextDecoder('utf-8', { fatal: true }).decode(content)
          );
          if (
            !manifest ||
            typeof manifest !== 'object' ||
            Array.isArray(manifest)
          )
            throw new Error('manifest-not-object');
        } catch {
          reasons.push('artifact-package-manifest-invalid');
        }
        if (
          manifest &&
          (manifest.name !== artifact.name ||
            manifest.version !== artifact.version)
        )
          reasons.push('artifact-package-identity-mismatch');
      }
      if (size > MAX_NPM_ARTIFACT_TEXT_FILE_BYTES && !content.includes(0)) {
        reasons.push('artifact-file-size-exceeded');
      } else if (!content.includes(0)) {
        try {
          const text = new TextDecoder('utf-8', { fatal: true }).decode(
            content
          );
          const artifactPath = `artifact:${artifact.location}/${canonical.slice(packageRoot.length + 1)}`;
          findings.push(...scanText(artifactPath, text, incompleteReasons));
        } catch {
          binaryFiles++;
        }
      } else {
        binaryFiles++;
      }
    } else if (type !== '5') {
      reasons.push('unsupported-tar-entry-type');
      break;
    }
    offset = bodyStart + Math.ceil(size / 512) * 512;
  }
  if (!sawTerminator) reasons.push('tar-terminator-missing');
  const scripts = manifest?.scripts;
  if (
    scripts !== undefined &&
    (!scripts || typeof scripts !== 'object' || Array.isArray(scripts))
  )
    reasons.push('artifact-package-scripts-invalid');
  let hasInstallScript = false;
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    const command = scripts?.[hook];
    if (command === undefined) continue;
    if (typeof command !== 'string') {
      reasons.push('artifact-package-scripts-invalid');
      continue;
    }
    hasInstallScript = true;
    if (!artifact.hasInstallScript) reasons.push('lifecycle-metadata-mismatch');
  }
  if (bindingGyp) hasInstallScript = true;
  // A registry/lock metadata bit set to true is conservative: the immutable
  // archive remains authoritative about whether an install hook exists. The
  // unsafe mismatch is an archive hook whose exact lock entry says none.
  if (hasInstallScript && !artifact.hasInstallScript)
    reasons.push('lifecycle-metadata-mismatch');
  if (!manifest) reasons.push('artifact-package-manifest-missing');
  if (hasInstallScript)
    reasons.push(`dependency-lifecycle-script-review:${artifact.location}`);
  if (binaryFiles > 0) reasons.push('artifact-binary-content-uninspected');
  return Object.freeze({
    files,
    bytes,
    findings: Object.freeze([...new Set(findings)].sort()),
    reasons: Object.freeze(
      [...new Set([...reasons, ...incompleteReasons])].sort()
    ),
    hasInstallScript,
    binaryFiles
  });
}

async function boundedResponseBytes(response, maximum) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maximum)
    throw new Error('artifact-size-budget-exceeded');
  if (!response.body) throw new Error('artifact-response-body-missing');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maximum) throw new Error('artifact-size-budget-exceeded');
      chunks.push(Buffer.from(next.value));
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, size);
}

export function parseStageAExceptionPolicy(text, now = Date.now()) {
  if (text === undefined) return Object.freeze({ entries: [], invalid: false });
  if (Buffer.byteLength(text) > MAX_STAGE_A_EXCEPTION_BYTES)
    return Object.freeze({ entries: [], invalid: true });
  let policy;
  try {
    policy = JSON.parse(text);
  } catch {
    return Object.freeze({ entries: [], invalid: true });
  }
  if (
    !policy ||
    typeof policy !== 'object' ||
    Array.isArray(policy) ||
    Object.keys(policy).some(
      (key) => !['version', 'exceptions'].includes(key)
    ) ||
    policy.version !== 1 ||
    !Array.isArray(policy.exceptions) ||
    policy.exceptions.length > MAX_STAGE_A_EXCEPTION_COUNT
  )
    return Object.freeze({ entries: [], invalid: true });
  const entries = [];
  for (const entry of policy.exceptions) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry))
      return Object.freeze({ entries: [], invalid: true });
    if (
      Object.keys(entry).some(
        (key) =>
          ![
            'id',
            'findingId',
            'reasonCode',
            'headInputSha256',
            'expiresAt',
            'rationale',
            'exactReason',
            'ownerAttestation'
          ].includes(key)
      )
    )
      return Object.freeze({ entries: [], invalid: true });
    const hasFindingId = typeof entry.findingId === 'string';
    const hasReasonCode = typeof entry.reasonCode === 'string';
    const expiresAt = Date.parse(entry.expiresAt);
    const ownerAttestation = entry.ownerAttestation;
    const hasOwnerAttestation = ownerAttestation !== undefined;
    if (hasOwnerAttestation) {
      const attestedAt = Date.parse(ownerAttestation?.attestedAt);
      const location = ownerAttestation?.artifactLocation;
      if (
        !hasReasonCode ||
        !OWNER_ATTESTABLE_ARTIFACT_REASONS.has(entry.reasonCode) ||
        typeof entry.exactReason !== 'string' ||
        !entry.exactReason.startsWith(entry.reasonCode + ':') ||
        entry.exactReason.length > 768 ||
        !ownerAttestation ||
        typeof ownerAttestation !== 'object' ||
        Array.isArray(ownerAttestation) ||
        Object.keys(ownerAttestation).some(
          (key) =>
            ![
              'owner',
              'headSha',
              'attestedAt',
              'artifactLocation',
              'artifactSha512'
            ].includes(key)
        ) ||
        !/^[A-Za-z0-9-]{1,39}$/u.test(ownerAttestation.owner ?? '') ||
        !/^[a-f0-9]{40}$/u.test(ownerAttestation.headSha ?? '') ||
        !/^[a-f0-9]{128}$/u.test(ownerAttestation.artifactSha512 ?? '') ||
        typeof location !== 'string' ||
        location.length > 256 ||
        !/^node_modules\/(?:[A-Za-z0-9@._-]+\/)*[A-Za-z0-9._-]+$/u.test(
          location
        ) ||
        location.split('/').some((part) => part === '.' || part === '..') ||
        !entry.exactReason.endsWith(':' + location) ||
        typeof ownerAttestation.attestedAt !== 'string' ||
        !Number.isFinite(attestedAt) ||
        new Date(attestedAt).toISOString() !== ownerAttestation.attestedAt ||
        attestedAt > now ||
        expiresAt > attestedAt + MAX_OWNER_ATTESTATION_LIFETIME_MS
      )
        return Object.freeze({ entries: [], invalid: true });
    } else if (entry.exactReason !== undefined) {
      return Object.freeze({ entries: [], invalid: true });
    }
    if (
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(entry.id ?? '') ||
      hasFindingId === hasReasonCode ||
      (hasFindingId && !/^[a-f0-9]{64}$/u.test(entry.findingId)) ||
      (hasReasonCode && !/^[a-z0-9][a-z0-9-]{0,63}$/u.test(entry.reasonCode)) ||
      !/^[a-f0-9]{64}$/u.test(entry.headInputSha256 ?? '') ||
      typeof entry.expiresAt !== 'string' ||
      !Number.isFinite(expiresAt) ||
      new Date(expiresAt).toISOString() !== entry.expiresAt ||
      typeof entry.rationale !== 'string' ||
      entry.rationale.trim().length < 20 ||
      entry.rationale.length > 512
    )
      return Object.freeze({ entries: [], invalid: true });
    if (expiresAt <= now) continue;
    if (expiresAt > now + MAX_STAGE_A_EXCEPTION_LIFETIME_MS)
      return Object.freeze({ entries: [], invalid: true });
    entries.push(
      Object.freeze({
        id: entry.id,
        ...(hasFindingId ? { findingId: entry.findingId } : {}),
        ...(hasReasonCode ? { reasonCode: entry.reasonCode } : {}),
        headInputSha256: entry.headInputSha256,
        expiresAt: entry.expiresAt,
        ...(hasOwnerAttestation
          ? {
              exactReason: entry.exactReason,
              ownerAttestation: Object.freeze({
                owner: ownerAttestation.owner,
                headSha: ownerAttestation.headSha,
                attestedAt: ownerAttestation.attestedAt,
                artifactLocation: ownerAttestation.artifactLocation,
                artifactSha512: ownerAttestation.artifactSha512
              })
            }
          : {})
      })
    );
  }
  if (new Set(entries.map((entry) => entry.id)).size !== entries.length)
    return Object.freeze({ entries: [], invalid: true });
  return Object.freeze({ entries: Object.freeze(entries), invalid: false });
}

/**
 * Match trusted-base exceptions against all findings and incomplete reasons
 * collected for one exact candidate tree. Dependency archive records are
 * intentionally included by callers; a matching exception never substitutes
 * for the artifact coverage checks required by the approval writer.
 */
export function matchingStageAExceptions(
  entries,
  headInputSha256,
  findingIds,
  incompleteReasons
) {
  const availableFindingIds = new Set(findingIds);
  const availableExactReasons = new Set(incompleteReasons);
  const availableReasonCodes = new Set(
    incompleteReasons.map((reason) => reason.split(':', 1)[0] ?? reason)
  );
  return Object.freeze(
    entries.filter(
      (entry) =>
        entry.headInputSha256 === headInputSha256 &&
        (entry.findingId
          ? availableFindingIds.has(entry.findingId)
          : entry.ownerAttestation
            ? availableExactReasons.has(entry.exactReason)
            : entry.reasonCode && availableReasonCodes.has(entry.reasonCode))
    )
  );
}

/**
 * Authorize a narrow, audited exception from the protected-base policy.
 * Its owner identity, tree, commit, exact unresolved reason and already
 * verified archive digest must all match the current immutable scan.
 * This does not authorize incomplete artifact downloads or signature checks.
 */
export function currentOwnerAttestation(
  entry,
  {
    repository,
    headSha,
    headInputSha256,
    incompleteReasons,
    verifiedArtifactSha512ByLocation
  }
) {
  const signed = entry?.ownerAttestation;
  const repoOwner = repository?.split('/');
  if (
    !signed ||
    !Array.isArray(repoOwner) ||
    repoOwner.length !== 2 ||
    signed.owner.toLowerCase() !== repoOwner[0].toLowerCase() ||
    entry.headInputSha256 !== headInputSha256 ||
    signed.headSha !== headSha ||
    !(incompleteReasons instanceof Set
      ? incompleteReasons.has(entry.exactReason)
      : Array.isArray(incompleteReasons) &&
        incompleteReasons.includes(entry.exactReason)) ||
    !OWNER_ATTESTABLE_ARTIFACT_REASONS.has(entry.reasonCode) ||
    !verifiedArtifactSha512ByLocation ||
    verifiedArtifactSha512ByLocation[signed.artifactLocation] !==
      signed.artifactSha512
  )
    return undefined;
  return Object.freeze({
    login: signed.owner,
    submittedAt: signed.attestedAt,
    commitId: signed.headSha
  });
}

export function currentMaintainerApproval(reviews, headSha, pullRequestAuthor) {
  if (
    !Array.isArray(reviews) ||
    !/^[0-9a-f]{40}$/iu.test(headSha ?? '') ||
    typeof pullRequestAuthor !== 'string' ||
    !pullRequestAuthor
  )
    return undefined;
  const latest = new Map();
  for (const [index, review] of reviews.entries()) {
    const login = review?.user?.login;
    const submittedAt = Date.parse(review?.submitted_at);
    if (
      typeof login !== 'string' ||
      !login ||
      !Number.isFinite(submittedAt) ||
      typeof review.commit_id !== 'string' ||
      !['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED', 'COMMENTED'].includes(
        review.state
      )
    )
      continue;
    const prior = latest.get(login.toLowerCase());
    if (
      !prior ||
      submittedAt > prior.submittedAt ||
      (submittedAt === prior.submittedAt && index > prior.index)
    )
      latest.set(login.toLowerCase(), {
        login,
        state: review.state,
        commitId: review.commit_id,
        association: review.author_association,
        submittedAt,
        index
      });
  }
  return [...latest.values()]
    .filter(
      (review) =>
        review.login.toLowerCase() !== pullRequestAuthor.toLowerCase() &&
        review.state === 'APPROVED' &&
        review.commitId === headSha &&
        ['OWNER', 'MEMBER', 'COLLABORATOR'].includes(review.association)
    )
    .sort(
      (left, right) =>
        left.submittedAt - right.submittedAt ||
        left.login.localeCompare(right.login)
    )
    .map((review) =>
      Object.freeze({
        login: review.login,
        submittedAt: new Date(review.submittedAt).toISOString(),
        commitId: review.commitId
      })
    )[0];
}

export async function fetchCurrentMaintainerApproval({
  repository,
  number,
  headSha,
  pullRequestAuthor,
  token,
  fetchImpl = globalThis.fetch
}) {
  const reviews = [];
  for (let page = 1; page <= 5; page++) {
    const url = `https://api.github.com/repos/${repository}/pulls/${number}/reviews?per_page=100&page=${page}`;
    const response = await fetchImpl(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': '2022-11-28'
      }
    });
    if (
      response.status !== 200 ||
      (response.url &&
        new URL(response.url).origin !== 'https://api.github.com')
    )
      throw new Error('maintainer-review-provider-unavailable');
    const bytes = await boundedResponseBytes(response, 1024 * 1024);
    let batch;
    try {
      batch = JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(bytes)
      );
    } catch {
      throw new Error('maintainer-review-response-invalid');
    }
    if (!Array.isArray(batch) || batch.length > 100)
      throw new Error('maintainer-review-response-invalid');
    reviews.push(...batch);
    const hasNext = /rel="next"/u.test(response.headers.get('link') ?? '');
    if (!hasNext)
      return currentMaintainerApproval(reviews, headSha, pullRequestAuthor);
    if (page === 5) throw new Error('maintainer-review-list-truncated');
  }
  throw new Error('maintainer-review-list-truncated');
}

export async function inspectNpmArtifacts(
  artifacts,
  {
    fetchImpl = globalThis.fetch,
    deadlineMs = MAX_ARTIFACT_DEADLINE_MS,
    allowedPublicScopes = []
  } = {}
) {
  const reasons = [];
  const findings = [];
  const coverage = {
    checked: 0,
    bytes: 0,
    files: 0,
    binaryFiles: 0,
    networkBytes: 0
  };
  if (artifacts.length > MAX_ARTIFACT_COUNT)
    return Object.freeze({
      reasons: Object.freeze(['artifact-count-budget-exceeded']),
      findings: Object.freeze([]),
      coverage: Object.freeze(coverage),
      verifiedArtifactSha512ByLocation: Object.freeze({}),
      verifiedBinaryFilesByLocation: Object.freeze({})
    });
  const startedAt = Date.now();
  const verifiedArtifactSha512ByLocation = new Map();
  const verifiedBinaryFilesByLocation = new Map();
  for (
    let start = 0;
    start < artifacts.length;
    start += MAX_ARTIFACT_CONCURRENCY
  ) {
    const batch = artifacts.slice(start, start + MAX_ARTIFACT_CONCURRENCY);
    const results = await Promise.all(
      batch.map(async (artifact) => {
        if (artifact.name.startsWith('@')) {
          const scope = artifact.name.split('/')[0];
          if (!allowedPublicScopes.includes(scope))
            return {
              reasons: [`scoped-artifact-fetch-withheld:${artifact.location}`]
            };
        }
        const url = new URL(artifact.resolved);
        if (
          url.protocol !== 'https:' ||
          url.hostname !== 'registry.npmjs.org' ||
          url.username ||
          url.password ||
          url.port ||
          url.search ||
          url.hash
        )
          return {
            reasons: [`unsupported-artifact-origin:${artifact.location}`]
          };
        const sha512 = artifact.integrity
          .split(/\s+/u)
          .find((part) => part.startsWith('sha512-'))
          ?.slice('sha512-'.length);
        if (!sha512)
          return { reasons: [`missing-sha512-integrity:${artifact.location}`] };
        const remaining = deadlineMs - (Date.now() - startedAt);
        if (remaining <= 0)
          return { reasons: ['artifact-inspection-deadline-exceeded'] };
        try {
          const response = await fetchImpl(url, {
            redirect: 'manual',
            signal: AbortSignal.timeout(Math.min(20_000, remaining)),
            headers: { accept: 'application/octet-stream' }
          });
          if (!response.ok || response.status >= 300)
            throw new Error('artifact-fetch-unavailable');
          if (
            response.url &&
            new URL(response.url).hostname !== 'registry.npmjs.org'
          )
            throw new Error('artifact-redirected-outside-registry');
          const archive = await boundedResponseBytes(
            response,
            MAX_ARTIFACT_BYTES
          );
          const actualDigest = createHash('sha512').update(archive).digest();
          if (actualDigest.toString('base64') !== sha512)
            throw new Error('artifact-integrity-mismatch');
          const inspected = inspectNpmTarball(archive, artifact);
          return {
            ...inspected,
            location: artifact.location,
            artifactSha512: actualDigest.toString('hex'),
            networkBytes: archive.length,
            reasons: inspected.reasons.map(
              (reason) => `${reason}:${artifact.location}`
            )
          };
        } catch (error) {
          const code =
            error instanceof Error &&
            [
              'artifact-size-budget-exceeded',
              'artifact-integrity-mismatch',
              'artifact-redirected-outside-registry'
            ].includes(error.message)
              ? error.message
              : 'artifact-fetch-or-inspection-failed';
          return { reasons: [`${code}:${artifact.location}`] };
        }
      })
    );
    for (const result of results) {
      reasons.push(...(result.reasons ?? []));
      findings.push(...(result.findings ?? []));
      if (
        typeof result.location === 'string' &&
        typeof result.artifactSha512 === 'string'
      )
        verifiedArtifactSha512ByLocation.set(
          result.location,
          result.artifactSha512
        );
      if (result.files !== undefined) {
        coverage.checked++;
        coverage.files += result.files;
        coverage.bytes += result.bytes ?? 0;
        coverage.binaryFiles += result.binaryFiles ?? 0;
        if (result.location && result.artifactSha512)
          verifiedBinaryFilesByLocation.set(
            result.location,
            result.binaryFiles ?? 0
          );
        coverage.networkBytes += result.networkBytes ?? 0;
        if (coverage.bytes > MAX_ARTIFACT_TOTAL_BYTES)
          reasons.push('artifact-total-content-budget-exceeded');
        if (coverage.networkBytes > MAX_ARTIFACT_TOTAL_BYTES)
          reasons.push('artifact-total-download-budget-exceeded');
        if (coverage.files > MAX_ARTIFACT_FILES)
          reasons.push('artifact-total-file-count-exceeded');
      }
    }
    if (
      coverage.bytes > MAX_ARTIFACT_TOTAL_BYTES ||
      coverage.networkBytes > MAX_ARTIFACT_TOTAL_BYTES ||
      coverage.files > MAX_ARTIFACT_FILES
    )
      break;
  }
  return Object.freeze({
    reasons: Object.freeze([...new Set(reasons)].sort()),
    findings: Object.freeze([...new Set(findings)].sort()),
    coverage: Object.freeze(coverage),
    verifiedArtifactSha512ByLocation: Object.freeze(
      Object.fromEntries(
        [...verifiedArtifactSha512ByLocation.entries()].sort(
          ([left], [right]) => left.localeCompare(right)
        )
      )
    ),
    verifiedBinaryFilesByLocation: Object.freeze(
      Object.fromEntries(
        [...verifiedBinaryFilesByLocation.entries()].sort(([left], [right]) =>
          left.localeCompare(right)
        )
      )
    )
  });
}

function cratesIoRegistrySource(source) {
  if (typeof source !== 'string' || !source.startsWith('registry+'))
    return false;
  try {
    const url = new URL(source.slice('registry+'.length));
    return (
      url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      !url.port &&
      !url.search &&
      !url.hash &&
      ((url.hostname === 'github.com' &&
        /^\/rust-lang\/crates\.io-index(?:\.git)?\/?$/u.test(url.pathname)) ||
        (url.hostname === 'index.crates.io' && url.pathname === '/'))
    );
  } catch {
    return false;
  }
}

function cargoLockRecordKey(record) {
  return `${record.name}\0${record.version}\0${record.source}`;
}

function goModuleRecordKey(record) {
  return `${record.module}\0${record.version}`;
}

/** Parse exact public module identities without invoking the Go toolchain. */
export function parseGoModuleArtifactInventory(
  moduleText,
  sumText,
  { modulePath = 'go.mod', sumPath = 'go.sum' } = {}
) {
  const reasons = [];
  if (
    typeof moduleText !== 'string' ||
    typeof sumText !== 'string' ||
    Buffer.byteLength(moduleText, 'utf8') > MAX_FILE_BYTES ||
    Buffer.byteLength(sumText, 'utf8') > MAX_FILE_BYTES ||
    !/(?:^|\/)go\.mod$/u.test(modulePath) ||
    !/(?:^|\/)go\.sum$/u.test(sumPath)
  )
    return Object.freeze({
      artifactRecords: Object.freeze([]),
      packageCount: 0,
      reasons: Object.freeze(['go-module-budget-or-path-invalid'])
    });

  // Replacements can select local trees or alternate module identities. They
  // need a different provenance proof and therefore remain explicitly
  // unsupported rather than being silently mapped to the public proxy.
  if (/^\s*replace\s+/mu.test(moduleText))
    reasons.push(`go-module-replacement-unverified:${modulePath}`);

  const required = new Map();
  let inRequireBlock = false;
  let invalidManifest = false;
  for (const originalLine of moduleText.split(/\r?\n/u)) {
    const line = originalLine.replace(/\/\/.*$/u, '').trim();
    if (!line) continue;
    if (/^require\s*\($/u.test(line)) {
      if (inRequireBlock) invalidManifest = true;
      inRequireBlock = true;
      continue;
    }
    if (line === ')') {
      if (!inRequireBlock) invalidManifest = true;
      inRequireBlock = false;
      continue;
    }
    const match = inRequireBlock
      ? /^(\S+)\s+(v\S+)$/u.exec(line)
      : /^require\s+(\S+)\s+(v\S+)$/u.exec(line);
    if (!match) continue;
    const [, module, version] = match;
    if (
      !module ||
      !version ||
      module.length > 512 ||
      version.length > 256 ||
      module.startsWith('.') ||
      module.includes('\\') ||
      module.includes('\0') ||
      version.includes('\0')
    ) {
      invalidManifest = true;
      continue;
    }
    required.set(`${module}\0${version}`, { module, version });
    if (required.size > MAX_ARTIFACT_COUNT) invalidManifest = true;
  }
  if (inRequireBlock || invalidManifest)
    reasons.push(`go-module-manifest-invalid:${modulePath}`);

  const sums = new Map();
  let invalidSum = false;
  for (const line of sumText.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    const match = /^(\S+)\s+(v\S+)\s+h1:([A-Za-z0-9+/]+={0,2})$/u.exec(
      line.trim()
    );
    if (!match) {
      invalidSum = true;
      continue;
    }
    const [, module, rawVersion, checksum] = match;
    if (!module || !rawVersion || !checksum) {
      invalidSum = true;
      continue;
    }
    if (rawVersion.endsWith('/go.mod')) continue;
    let digest;
    try {
      digest = Buffer.from(checksum, 'base64');
    } catch {
      invalidSum = true;
      continue;
    }
    if (digest.length !== 32 || digest.toString('base64') !== checksum) {
      invalidSum = true;
      continue;
    }
    const key = `${module}\0${rawVersion}`;
    const prior = sums.get(key);
    if (prior && prior !== checksum) {
      sums.delete(key);
      reasons.push(`go-module-checksum-conflict:${sumPath}`);
    } else if (!prior) sums.set(key, checksum);
  }
  if (invalidSum) reasons.push(`go-sum-invalid:${sumPath}`);

  const records = new Map();
  for (const item of required.values()) {
    const key = `${item.module}\0${item.version}`;
    const checksum = sums.get(key);
    if (!checksum) {
      reasons.push(`go-module-checksum-missing:${modulePath}`);
      continue;
    }
    const record = Object.freeze({
      location: `go-module/${Buffer.from(modulePath).toString('base64url')}/${Buffer.from(item.module).toString('base64url')}@${Buffer.from(item.version).toString('base64url')}#${Buffer.from(checksum, 'base64').toString('hex')}`,
      module: item.module,
      version: item.version,
      checksum
    });
    records.set(goModuleRecordKey(record), record);
  }
  return Object.freeze({
    artifactRecords: Object.freeze(
      [...records.values()].sort((left, right) =>
        left.location.localeCompare(right.location)
      )
    ),
    packageCount: required.size,
    reasons: Object.freeze([...new Set(reasons)].sort())
  });
}

function escapeGoModuleComponent(value) {
  let escaped = '';
  for (const character of value) {
    if (character === '!') escaped += '!!';
    else if (character >= 'A' && character <= 'Z')
      escaped += `!${character.toLowerCase()}`;
    else escaped += character;
  }
  return escaped;
}

/** Inspect and hash a Go module ZIP without extracting or executing it. */
export function inspectGoModuleZip(
  archive,
  artifact,
  {
    maxUnpackedBytes = MAX_ARTIFACT_UNPACKED_BYTES,
    maxFiles = MAX_ARTIFACT_FILES
  } = {}
) {
  const reasons = [];
  const findings = [];
  if (!Buffer.isBuffer(archive) || archive.length > MAX_ARTIFACT_BYTES)
    return Object.freeze({
      files: 0,
      bytes: 0,
      findings: Object.freeze([]),
      reasons: Object.freeze(['go-artifact-size-or-identity-invalid']),
      binaryFiles: 0
    });
  // The proxy URL is escaped, but the module ZIP itself uses the original
  // module path and version as its root (golang.org/ref/mod#zip-path).
  const expectedRoot = `${artifact.module}@${artifact.version}/`;
  const minimumEocd = Math.max(0, archive.length - 65_557);
  let eocd = -1;
  for (let offset = archive.length - 22; offset >= minimumEocd; offset--) {
    if (archive.readUInt32LE(offset) === 0x06054b50) {
      eocd = offset;
      break;
    }
  }
  if (eocd < 0)
    return Object.freeze({
      files: 0,
      bytes: 0,
      findings: Object.freeze([]),
      reasons: Object.freeze(['go-zip-directory-invalid']),
      binaryFiles: 0
    });
  const entryCount = archive.readUInt16LE(eocd + 10);
  const directoryBytes = archive.readUInt32LE(eocd + 12);
  const directoryOffset = archive.readUInt32LE(eocd + 16);
  if (
    archive.readUInt16LE(eocd + 4) !== 0 ||
    archive.readUInt16LE(eocd + 6) !== 0 ||
    archive.readUInt16LE(eocd + 8) !== entryCount ||
    entryCount > maxFiles ||
    directoryOffset + directoryBytes > eocd
  )
    reasons.push('go-zip-directory-invalid');
  const entries = [];
  const seen = new Set();
  let cursor = directoryOffset;
  let declaredBytes = 0;
  for (let index = 0; index < entryCount && reasons.length === 0; index++) {
    if (
      cursor + 46 > archive.length ||
      archive.readUInt32LE(cursor) !== 0x02014b50
    ) {
      reasons.push('go-zip-directory-invalid');
      break;
    }
    const flags = archive.readUInt16LE(cursor + 8);
    const method = archive.readUInt16LE(cursor + 10);
    const compressedSize = archive.readUInt32LE(cursor + 20);
    const size = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const commentLength = archive.readUInt16LE(cursor + 32);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const next = cursor + 46 + nameLength + extraLength + commentLength;
    if (
      next > archive.length ||
      (flags & 1) !== 0 ||
      ![0, 8].includes(method) ||
      size > MAX_ARTIFACT_FILE_BYTES ||
      compressedSize > MAX_ARTIFACT_BYTES
    ) {
      reasons.push('go-zip-entry-invalid');
      break;
    }
    let name;
    try {
      name = new TextDecoder('utf-8', { fatal: true }).decode(
        archive.subarray(cursor + 46, cursor + 46 + nameLength)
      );
    } catch {
      reasons.push('go-zip-entry-name-invalid');
      break;
    }
    if (
      !name.startsWith(expectedRoot) ||
      name === expectedRoot ||
      name.includes('\\') ||
      name.includes('\0') ||
      name.split('/').some((part) => part === '.' || part === '..') ||
      name.endsWith('/') ||
      seen.has(name)
    ) {
      reasons.push('go-zip-entry-name-invalid');
      break;
    }
    seen.add(name);
    declaredBytes += size;
    if (declaredBytes > maxUnpackedBytes) {
      reasons.push('go-artifact-content-budget-exceeded');
      break;
    }
    entries.push({ name, method, compressedSize, size, localOffset });
    cursor = next;
  }
  if (cursor !== directoryOffset + directoryBytes)
    reasons.push('go-zip-directory-invalid');

  const hashEntries = [];
  let bytes = 0;
  let binaryFiles = 0;
  for (const entry of entries) {
    const { localOffset } = entry;
    if (
      localOffset + 30 > archive.length ||
      archive.readUInt32LE(localOffset) !== 0x04034b50
    ) {
      reasons.push('go-zip-local-header-invalid');
      break;
    }
    const nameLength = archive.readUInt16LE(localOffset + 26);
    const extraLength = archive.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + nameLength + extraLength;
    const dataEnd = dataStart + entry.compressedSize;
    if (dataEnd > archive.length) {
      reasons.push('go-zip-entry-invalid');
      break;
    }
    const localName = archive
      .subarray(localOffset + 30, localOffset + 30 + nameLength)
      .toString('utf8');
    if (localName !== entry.name) {
      reasons.push('go-zip-local-header-invalid');
      break;
    }
    let content;
    try {
      const compressed = archive.subarray(dataStart, dataEnd);
      content =
        entry.method === 0
          ? compressed
          : inflateRawSync(compressed, { maxOutputLength: entry.size });
    } catch {
      reasons.push('go-zip-entry-decompression-failed');
      break;
    }
    if (content.length !== entry.size) {
      reasons.push('go-zip-entry-size-mismatch');
      break;
    }
    bytes += content.length;
    const relativePath = entry.name.slice(expectedRoot.length);
    hashEntries.push({
      name: entry.name,
      digest: createHash('sha256').update(content).digest('hex')
    });
    if (content.includes(0)) binaryFiles++;
    else {
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(content);
        findings.push(
          ...scanText(
            `artifact:${artifact.location}/${relativePath}`,
            text,
            reasons
          )
        );
      } catch {
        binaryFiles++;
      }
    }
  }
  hashEntries.sort((left, right) =>
    Buffer.compare(Buffer.from(left.name), Buffer.from(right.name))
  );
  const actualChecksum = createHash('sha256')
    .update(
      hashEntries.map(({ name, digest }) => `${digest}  ${name}\n`).join('')
    )
    .digest('base64');
  if (actualChecksum !== artifact.checksum)
    reasons.push('go-artifact-integrity-mismatch');
  if (binaryFiles > 0) reasons.push('go-artifact-binary-content-uninspected');
  return Object.freeze({
    files: entries.length,
    bytes,
    findings: Object.freeze([...new Set(findings)].sort()),
    reasons: Object.freeze([...new Set(reasons)].sort()),
    binaryFiles
  });
}

export async function inspectGoArtifacts(
  artifacts,
  {
    fetchImpl = globalThis.fetch,
    deadlineMs = MAX_ARTIFACT_DEADLINE_MS,
    maxCount = MAX_ARTIFACT_COUNT,
    maxTotalBytes = MAX_ARTIFACT_TOTAL_BYTES,
    maxTotalNetworkBytes = MAX_ARTIFACT_TOTAL_BYTES,
    maxFiles = MAX_ARTIFACT_FILES
  } = {}
) {
  const reasons = [];
  const findings = [];
  const coverage = {
    checked: 0,
    bytes: 0,
    files: 0,
    binaryFiles: 0,
    networkBytes: 0
  };
  const verifiedArtifactSha256ByLocation = new Map();
  if (artifacts.length > maxCount)
    return Object.freeze({
      reasons: Object.freeze(['go-artifact-count-budget-exceeded']),
      findings: Object.freeze([]),
      coverage: Object.freeze(coverage),
      verifiedArtifactSha256ByLocation: Object.freeze({})
    });
  const startedAt = Date.now();
  for (const artifact of artifacts) {
    if (Date.now() - startedAt >= deadlineMs) {
      reasons.push('go-artifact-inspection-deadline-exceeded');
      break;
    }
    if (
      typeof artifact.module !== 'string' ||
      typeof artifact.version !== 'string' ||
      typeof artifact.checksum !== 'string' ||
      !/^go-module\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+@[A-Za-z0-9_-]+#[a-f0-9]{64}$/u.test(
        artifact.location ?? ''
      )
    ) {
      reasons.push('go-artifact-identity-invalid');
      continue;
    }
    const escapedModule = escapeGoModuleComponent(artifact.module);
    const escapedVersion = escapeGoModuleComponent(artifact.version);
    const url = new URL(
      `https://proxy.golang.org/${escapedModule}/@v/${escapedVersion}.zip`
    );
    try {
      const response = await fetchImpl(url, {
        redirect: 'follow',
        signal: AbortSignal.timeout(
          Math.max(1, deadlineMs - (Date.now() - startedAt))
        )
      });
      if (!response?.ok) throw new Error('go-artifact-fetch-failed');
      const finalUrl = new URL(response.url || url);
      if (
        !(
          (finalUrl.origin === url.origin &&
            finalUrl.pathname === url.pathname &&
            !finalUrl.search) ||
          (finalUrl.protocol === 'https:' &&
            finalUrl.hostname === 'storage.googleapis.com')
        ) ||
        finalUrl.hash
      )
        throw new Error('go-artifact-redirected-outside-proxy');
      const networkBudget = Math.max(
        0,
        maxTotalNetworkBytes - coverage.networkBytes
      );
      if (networkBudget === 0)
        throw new Error('go-artifact-total-download-budget-exceeded');
      const archive = await boundedResponseBytes(
        response,
        Math.min(MAX_ARTIFACT_BYTES, networkBudget)
      );
      const inspected = inspectGoModuleZip(archive, artifact, {
        maxUnpackedBytes: Math.max(0, maxTotalBytes - coverage.bytes),
        maxFiles: Math.max(0, maxFiles - coverage.files)
      });
      const archiveSha256 = createHash('sha256').update(archive).digest('hex');
      coverage.networkBytes += archive.length;
      coverage.bytes += inspected.bytes;
      coverage.files += inspected.files;
      coverage.binaryFiles += inspected.binaryFiles;
      findings.push(...inspected.findings);
      reasons.push(
        ...inspected.reasons.map((reason) => `${reason}:${artifact.location}`)
      );
      if (inspected.reasons.length === 0) {
        coverage.checked++;
        verifiedArtifactSha256ByLocation.set(artifact.location, archiveSha256);
      }
    } catch (error) {
      const code =
        error instanceof Error &&
        [
          'artifact-size-budget-exceeded',
          'go-artifact-redirected-outside-proxy',
          'go-artifact-total-download-budget-exceeded'
        ].includes(error.message)
          ? error.message
          : 'go-artifact-fetch-or-inspection-failed';
      reasons.push(`${code}:${artifact.location}`);
    }
  }
  return Object.freeze({
    reasons: Object.freeze([...new Set(reasons)].sort()),
    findings: Object.freeze([...new Set(findings)].sort()),
    coverage: Object.freeze(coverage),
    verifiedArtifactSha256ByLocation: Object.freeze(
      Object.fromEntries(
        [...verifiedArtifactSha256ByLocation].sort(([left], [right]) =>
          left.localeCompare(right)
        )
      )
    )
  });
}

/** Parse only exact crates.io package identities from a bounded Cargo.lock. */
export function parseCargoLockArtifactInventory(
  lockText,
  { lockPath = 'Cargo.lock', rootPackage, rootPackages = [] } = {}
) {
  const reasons = [];
  if (
    typeof lockText !== 'string' ||
    Buffer.byteLength(lockText, 'utf8') > MAX_FILE_BYTES ||
    typeof lockPath !== 'string' ||
    !lockPath.endsWith('Cargo.lock')
  )
    return Object.freeze({
      artifactRecords: Object.freeze([]),
      packageCount: 0,
      reasons: Object.freeze(['cargo-lock-budget-or-path-invalid'])
    });

  let document;
  try {
    document = parseToml(lockText, { unsafeKeyBehaviour: 'throw' });
  } catch {
    return Object.freeze({
      artifactRecords: Object.freeze([]),
      packageCount: 0,
      reasons: Object.freeze(['cargo-lock-invalid'])
    });
  }
  if (
    !document ||
    typeof document !== 'object' ||
    Array.isArray(document) ||
    ![3, 4].includes(document.version) ||
    !Array.isArray(document.package) ||
    document.package.length > MAX_ARTIFACT_COUNT
  )
    return Object.freeze({
      artifactRecords: Object.freeze([]),
      packageCount: Array.isArray(document?.package)
        ? document.package.length
        : 0,
      reasons: Object.freeze(['cargo-lock-schema-or-budget-invalid'])
    });

  const records = new Map();
  const localPackageIds = new Set(
    [rootPackage, ...rootPackages]
      .filter(
        (item) =>
          item &&
          typeof item.name === 'string' &&
          typeof item.version === 'string'
      )
      .map((item) => `${item.name}\0${item.version}`)
  );
  let invalidPackage = false;
  for (const item of document.package) {
    if (
      !item ||
      typeof item !== 'object' ||
      Array.isArray(item) ||
      typeof item.name !== 'string' ||
      !/^[A-Za-z0-9_-]{1,128}$/u.test(item.name) ||
      typeof item.version !== 'string' ||
      !/^[0-9][A-Za-z0-9.+-]{0,127}$/u.test(item.version)
    ) {
      invalidPackage = true;
      continue;
    }

    if (item.source === undefined) {
      if (localPackageIds.has(`${item.name}\0${item.version}`)) continue;
      reasons.push(`cargo-local-package-unverified:${lockPath}`);
      continue;
    }
    if (!cratesIoRegistrySource(item.source)) {
      reasons.push(`cargo-source-unverified:${lockPath}`);
      continue;
    }
    if (
      typeof item.checksum !== 'string' ||
      !/^[a-f0-9]{64}$/iu.test(item.checksum)
    ) {
      reasons.push(`cargo-checksum-missing-or-invalid:${lockPath}`);
      continue;
    }

    const record = {
      location: `cargo-lock/${Buffer.from(lockPath).toString('base64url')}/${item.name}@${item.version}#${item.checksum.toLowerCase()}`,
      name: item.name,
      version: item.version,
      source: item.source,
      checksum: item.checksum.toLowerCase()
    };
    const key = cargoLockRecordKey(record);
    const prior = records.get(key);
    if (prior && prior.checksum !== record.checksum) {
      records.delete(key);
      reasons.push(`cargo-package-checksum-conflict:${lockPath}`);
    } else if (!prior) records.set(key, Object.freeze(record));
  }
  if (invalidPackage) reasons.push(`cargo-package-record-invalid:${lockPath}`);

  return Object.freeze({
    artifactRecords: Object.freeze(
      [...records.values()].sort((left, right) =>
        left.location.localeCompare(right.location)
      )
    ),
    packageCount: document.package.length,
    reasons: Object.freeze([...new Set(reasons)].sort())
  });
}

/** Inspect a crates.io .crate archive without extracting or executing it. */
export function inspectCargoCrateTarball(
  archive,
  artifact,
  {
    maxUnpackedBytes = MAX_ARTIFACT_UNPACKED_BYTES,
    maxFiles = MAX_ARTIFACT_FILES
  } = {}
) {
  if (
    !Buffer.isBuffer(archive) ||
    archive.length > MAX_ARTIFACT_BYTES ||
    !/^[A-Za-z0-9_-]{1,128}$/u.test(artifact?.name ?? '') ||
    !/^[0-9][A-Za-z0-9.+-]{0,127}$/u.test(artifact?.version ?? '')
  )
    return Object.freeze({
      files: 0,
      bytes: 0,
      findings: Object.freeze([]),
      reasons: Object.freeze(['cargo-artifact-size-or-identity-invalid']),
      binaryFiles: 0,
      hasBuildScript: false,
      isProcMacro: false
    });

  const packageRoot = `${artifact.name}-${artifact.version}`;
  let unpacked;
  try {
    unpacked = gunzipSync(archive, {
      maxOutputLength: Math.min(MAX_ARTIFACT_UNPACKED_BYTES, maxUnpackedBytes)
    });
  } catch {
    return Object.freeze({
      files: 0,
      bytes: 0,
      findings: Object.freeze([]),
      reasons: Object.freeze(['cargo-artifact-gzip-invalid-or-over-budget']),
      binaryFiles: 0,
      hasBuildScript: false,
      isProcMacro: false
    });
  }

  const reasons = [];
  if (unpacked.length > 1024 * 1024 && unpacked.length > archive.length * 200)
    reasons.push('cargo-artifact-compression-ratio-exceeded');
  const findings = [];
  const seen = new Set();
  const textPaths = new Set();
  let offset = 0;
  let entries = 0;
  let files = 0;
  let bytes = 0;
  let binaryFiles = 0;
  let manifest;
  let sawTerminator = false;
  while (offset + 512 <= unpacked.length) {
    const header = unpacked.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      sawTerminator = true;
      if (unpacked.length - offset < 1024)
        reasons.push('cargo-tar-terminator-truncated');
      if (unpacked.subarray(offset).some((byte) => byte !== 0))
        reasons.push('cargo-tar-trailing-data');
      offset = unpacked.length;
      break;
    }

    let canonical;
    let size;
    try {
      let name = readTarText(header, 0, 100);
      const prefix = readTarText(header, 345, 155);
      if (prefix) name = `${prefix}/${name}`;
      canonical = safeTarName(name, packageRoot);
      size = readTarOctal(header, 124, 12);
      const declaredChecksum = readTarOctal(header, 148, 8);
      let checksum = 0;
      for (let index = 0; index < 512; index++)
        checksum += index >= 148 && index < 156 ? 32 : (header[index] ?? 0);
      if (checksum !== declaredChecksum)
        reasons.push('cargo-tar-header-checksum-invalid');
    } catch (error) {
      reasons.push(
        error instanceof Error ? error.message : 'cargo-tar-header-invalid'
      );
      break;
    }

    const type = String.fromCharCode(header[156] ?? 0);
    const bodyStart = offset + 512;
    const bodyEnd = bodyStart + size;
    if (
      size > MAX_ARTIFACT_FILE_BYTES ||
      bodyEnd > unpacked.length ||
      !Number.isSafeInteger(bodyEnd)
    ) {
      reasons.push('cargo-artifact-file-size-exceeded');
      break;
    }
    entries++;
    if (entries > MAX_ARTIFACT_FILES) {
      reasons.push('cargo-artifact-content-budget-exceeded');
      break;
    }
    if (['x', 'g', 'L', 'K', '1', '2', 'S'].includes(type)) {
      reasons.push('cargo-tar-entry-type-unsupported');
      break;
    }
    if (type === '0' || type === '\0' || type === '7') {
      if (canonical === packageRoot) {
        reasons.push('cargo-tar-file-path-invalid');
        break;
      }
      files++;
      bytes += size;
      if (files > maxFiles || bytes > maxUnpackedBytes) {
        reasons.push('cargo-artifact-content-budget-exceeded');
        break;
      }
      if (seen.has(canonical)) {
        reasons.push('cargo-tar-duplicate-path');
        break;
      }
      seen.add(canonical);
      const content = unpacked.subarray(bodyStart, bodyEnd);
      const relativePath = canonical.slice(packageRoot.length + 1);
      if (relativePath === 'Cargo.toml') {
        try {
          manifest = parseToml(
            new TextDecoder('utf-8', { fatal: true }).decode(content),
            {
              unsafeKeyBehaviour: 'throw'
            }
          );
          if (
            !manifest ||
            typeof manifest !== 'object' ||
            Array.isArray(manifest)
          )
            throw new Error('cargo-manifest-not-object');
        } catch {
          reasons.push('cargo-artifact-manifest-invalid');
        }
      }
      if (!content.includes(0)) {
        try {
          const text = new TextDecoder('utf-8', { fatal: true }).decode(
            content
          );
          textPaths.add(relativePath);
          findings.push(
            ...scanText(
              `artifact:${artifact.location}/${relativePath}`,
              text,
              reasons
            )
          );
        } catch {
          binaryFiles++;
        }
      } else {
        binaryFiles++;
      }
    } else if (type === '5') {
      if (size !== 0) {
        reasons.push('cargo-tar-directory-entry-invalid');
        break;
      }
    } else {
      reasons.push('cargo-tar-entry-type-unsupported');
      break;
    }
    offset = bodyStart + Math.ceil(size / 512) * 512;
  }
  if (!sawTerminator) reasons.push('cargo-tar-terminator-missing');

  const packageManifest = manifest?.package;
  if (
    !packageManifest ||
    packageManifest.name !== artifact.name ||
    packageManifest.version !== artifact.version
  )
    reasons.push('cargo-artifact-package-identity-mismatch');
  const explicitBuild = packageManifest?.build;
  let buildScriptPath = 'build.rs';
  if (typeof explicitBuild === 'string') {
    const normalized = path.posix.normalize(
      explicitBuild.replaceAll('\\', '/')
    );
    if (
      !explicitBuild ||
      normalized === '..' ||
      normalized.startsWith('../') ||
      normalized.startsWith('/') ||
      /^[A-Za-z]:/u.test(normalized) ||
      normalized.includes('\0')
    )
      reasons.push('cargo-build-script-path-invalid');
    else buildScriptPath = normalized;
  } else if (
    explicitBuild !== undefined &&
    typeof explicitBuild !== 'boolean'
  ) {
    reasons.push('cargo-build-script-setting-invalid');
  }
  const hasBuildScript =
    explicitBuild !== false && textPaths.has(buildScriptPath);
  if (
    explicitBuild === true ||
    (typeof explicitBuild === 'string' && explicitBuild.length > 0)
  ) {
    if (!textPaths.has(buildScriptPath))
      reasons.push('cargo-build-script-missing');
  }
  if (hasBuildScript)
    reasons.push(`cargo-build-script-review:${artifact.location}`);
  const lib = manifest?.lib;
  const crateTypes = Array.isArray(lib?.['crate-type'])
    ? lib['crate-type']
    : [];
  if (
    lib?.['crate-type'] !== undefined &&
    (!Array.isArray(lib['crate-type']) ||
      lib['crate-type'].some((crateType) => typeof crateType !== 'string'))
  )
    reasons.push('cargo-crate-type-invalid');
  if (
    lib?.['proc-macro'] !== undefined &&
    typeof lib['proc-macro'] !== 'boolean'
  )
    reasons.push('cargo-proc-macro-setting-invalid');
  const isProcMacro =
    crateTypes.includes('proc-macro') || lib?.['proc-macro'] === true;
  if (isProcMacro) reasons.push(`cargo-proc-macro-review:${artifact.location}`);
  if (binaryFiles > 0)
    reasons.push('cargo-artifact-binary-content-uninspected');

  return Object.freeze({
    files,
    bytes,
    findings: Object.freeze([...new Set(findings)].sort()),
    reasons: Object.freeze([...new Set(reasons)].sort()),
    binaryFiles,
    hasBuildScript,
    isProcMacro
  });
}

export async function inspectCargoArtifacts(
  artifacts,
  {
    fetchImpl = globalThis.fetch,
    deadlineMs = MAX_ARTIFACT_DEADLINE_MS,
    maxCount = MAX_ARTIFACT_COUNT,
    maxTotalBytes = MAX_ARTIFACT_TOTAL_BYTES,
    maxTotalNetworkBytes = MAX_ARTIFACT_TOTAL_BYTES,
    maxFiles = MAX_ARTIFACT_FILES
  } = {}
) {
  const reasons = [];
  const findings = [];
  const coverage = {
    checked: 0,
    bytes: 0,
    files: 0,
    binaryFiles: 0,
    networkBytes: 0
  };
  const verifiedArtifactSha256ByLocation = new Map();
  if (artifacts.length > maxCount)
    return Object.freeze({
      reasons: Object.freeze(['cargo-artifact-count-budget-exceeded']),
      findings: Object.freeze([]),
      coverage: Object.freeze(coverage),
      verifiedArtifactSha256ByLocation: Object.freeze({})
    });

  const startedAt = Date.now();
  for (let start = 0; start < artifacts.length; start++) {
    const batch = artifacts.slice(start, start + 1);
    const results = await Promise.all(
      batch.map(async (artifact) => {
        if (
          !/^[A-Za-z0-9_-]{1,128}$/u.test(artifact.name ?? '') ||
          !/^[0-9][A-Za-z0-9.+-]{0,127}$/u.test(artifact.version ?? '') ||
          !/^[a-f0-9]{64}$/iu.test(artifact.checksum ?? '') ||
          !cratesIoRegistrySource(artifact.source) ||
          !/^cargo-lock\/[A-Za-z0-9_-]+\//u.test(artifact.location ?? '') ||
          !artifact.location.endsWith(
            `/${artifact.name}@${artifact.version}#${artifact.checksum}`
          )
        )
          return { reasons: ['cargo-artifact-identity-invalid'] };
        const url = new URL(
          `https://static.crates.io/crates/${artifact.name}/${artifact.name}-${artifact.version}.crate`
        );
        const remaining = deadlineMs - (Date.now() - startedAt);
        if (remaining <= 0)
          return { reasons: ['cargo-artifact-inspection-deadline-exceeded'] };
        try {
          const response = await fetchImpl(url, {
            redirect: 'manual',
            signal: AbortSignal.timeout(Math.min(20_000, remaining)),
            headers: { accept: 'application/gzip, application/octet-stream' }
          });
          if (!response.ok || response.status >= 300)
            throw new Error('cargo-artifact-fetch-unavailable');
          if (response.url) {
            const finalUrl = new URL(response.url);
            if (
              finalUrl.origin !== 'https://static.crates.io' ||
              finalUrl.pathname !== url.pathname ||
              finalUrl.search ||
              finalUrl.hash
            )
              throw new Error('cargo-artifact-redirected-outside-registry');
          }
          const remainingNetworkBytes = Math.max(
            0,
            maxTotalNetworkBytes - coverage.networkBytes
          );
          if (remainingNetworkBytes === 0)
            throw new Error('cargo-artifact-total-download-budget-exceeded');
          const archive = await boundedResponseBytes(
            response,
            Math.min(MAX_ARTIFACT_BYTES, remainingNetworkBytes)
          );
          const actualDigest = createHash('sha256')
            .update(archive)
            .digest('hex');
          if (actualDigest !== artifact.checksum.toLowerCase())
            throw new Error('cargo-artifact-integrity-mismatch');
          const inspected = inspectCargoCrateTarball(archive, artifact, {
            maxUnpackedBytes: Math.max(0, maxTotalBytes - coverage.bytes),
            maxFiles: Math.max(0, maxFiles - coverage.files)
          });
          return {
            ...inspected,
            location: artifact.location,
            artifactSha256: actualDigest,
            networkBytes: archive.length,
            reasons: inspected.reasons.map(
              (reason) => `${reason}:${artifact.location}`
            )
          };
        } catch (error) {
          const code =
            error instanceof Error &&
            [
              'artifact-size-budget-exceeded',
              'cargo-artifact-integrity-mismatch',
              'cargo-artifact-redirected-outside-registry',
              'cargo-artifact-total-download-budget-exceeded'
            ].includes(error.message)
              ? error.message
              : 'cargo-artifact-fetch-or-inspection-failed';
          return { reasons: [`${code}:${artifact.location}`] };
        }
      })
    );
    for (const result of results) {
      reasons.push(...(result.reasons ?? []));
      findings.push(...(result.findings ?? []));
      if (
        typeof result.location === 'string' &&
        typeof result.artifactSha256 === 'string'
      )
        verifiedArtifactSha256ByLocation.set(
          result.location,
          result.artifactSha256
        );
      if (result.files !== undefined) {
        coverage.checked++;
        coverage.files += result.files;
        coverage.bytes += result.bytes ?? 0;
        coverage.binaryFiles += result.binaryFiles ?? 0;
        coverage.networkBytes += result.networkBytes ?? 0;
        if (coverage.bytes > maxTotalBytes)
          reasons.push('cargo-artifact-total-content-budget-exceeded');
        if (coverage.networkBytes > maxTotalNetworkBytes)
          reasons.push('cargo-artifact-total-download-budget-exceeded');
        if (coverage.files > maxFiles)
          reasons.push('cargo-artifact-total-file-count-exceeded');
      }
    }
    if (
      coverage.bytes > maxTotalBytes ||
      coverage.networkBytes > maxTotalNetworkBytes ||
      coverage.files > maxFiles
    )
      break;
  }
  return Object.freeze({
    reasons: Object.freeze([...new Set(reasons)].sort()),
    findings: Object.freeze([...new Set(findings)].sort()),
    coverage: Object.freeze(coverage),
    verifiedArtifactSha256ByLocation: Object.freeze(
      Object.fromEntries(
        [...verifiedArtifactSha256ByLocation.entries()].sort(
          ([left], [right]) => left.localeCompare(right)
        )
      )
    )
  });
}

export function verifyCargoArtifactPolicy(artifacts, policyText) {
  if (artifacts.length === 0)
    return Object.freeze({
      policySha256: null,
      reasons: Object.freeze([])
    });
  let policy;
  try {
    policy = parseCargoArtifactPolicy(policyText);
  } catch {
    return Object.freeze({
      policySha256: null,
      reasons: Object.freeze(['cargo-artifact-policy-unavailable-or-invalid'])
    });
  }
  const policySha256 = canonicalJsonSha256(policy);
  const expected = new Map();
  const reasons = [];
  for (const artifact of artifacts) {
    const identity = `${artifact.name}@${artifact.version}`;
    const prior = expected.get(identity);
    if (prior !== undefined && prior !== artifact.checksum)
      reasons.push('cargo-artifact-lock-identity-conflict');
    expected.set(identity, artifact.checksum);
  }
  const policyPackages = policy.packages;
  for (const [identity, checksum] of expected) {
    if (policyPackages[identity] === undefined)
      reasons.push(`cargo-artifact-policy-entry-missing:${identity}`);
    else if (policyPackages[identity] !== checksum)
      reasons.push(`cargo-artifact-policy-digest-mismatch:${identity}`);
  }
  for (const identity of Object.keys(policyPackages))
    if (!expected.has(identity))
      reasons.push(`cargo-artifact-policy-entry-unused:${identity}`);
  return Object.freeze({
    policySha256,
    reasons: Object.freeze([...new Set(reasons)].sort())
  });
}

// Retained for test and API compatibility; Stage A now inspects every exact
// locked identity, including unchanged packages, before any install occurs.
export const inspectChangedNpmArtifacts = inspectNpmArtifacts;

function readCommitBlob(repo, commit, name) {
  const raw = git(repo, ['ls-tree', '-z', commit, '--', name], 4096);
  if (raw.length === 0) return undefined;
  const record = raw.toString('utf8').split('\0')[0] ?? '';
  const match = record.match(/^(100644|100755) blob ([0-9a-f]{40,64})\t/u);
  if (!match) throw new Error(`Unsupported Git object for ${name}`);
  const content = catFileBatch(repo, [match[2]]).get(match[2]);
  if (!content || content.length > MAX_FILE_BYTES)
    throw new Error(`${name} is missing or exceeds Stage A file budget`);
  return new TextDecoder('utf-8', { fatal: true }).decode(content);
}

function parseCargoManifest(text) {
  if (
    typeof text !== 'string' ||
    Buffer.byteLength(text, 'utf8') > MAX_FILE_BYTES
  )
    return undefined;
  try {
    const manifest = parseToml(text, { unsafeKeyBehaviour: 'throw' });
    return manifest && typeof manifest === 'object' && !Array.isArray(manifest)
      ? manifest
      : undefined;
  } catch {
    return undefined;
  }
}

function parseCargoManifestIdentity(manifest, workspaceManifest = manifest) {
  const name = manifest?.package?.name;
  const packageVersion = manifest?.package?.version;
  const version =
    packageVersion &&
    typeof packageVersion === 'object' &&
    !Array.isArray(packageVersion) &&
    packageVersion.workspace === true
      ? workspaceManifest?.workspace?.package?.version
      : packageVersion;
  return typeof name === 'string' && typeof version === 'string'
    ? { name, version }
    : undefined;
}

function cargoManifestDirectory(manifestPath) {
  const directory = path.posix.dirname(manifestPath);
  return directory === '.' ? '' : directory;
}

function isDependencyFixturePath(name) {
  return /(?:^|\/)(?:__fixtures__|fixtures|tests?)(?:\/|$)/iu.test(name);
}

function inspectCargoLockfiles(repo, commit, tree) {
  const resolvedTree =
    tree ?? parseTree(git(repo, ['ls-tree', '-rz', '--full-tree', commit]));
  const lockfiles = resolvedTree.blobs.filter(
    (blob) =>
      !isDependencyFixturePath(blob.path) &&
      /(?:^|\/)Cargo\.lock$/u.test(blob.path)
  );
  const manifests = resolvedTree.blobs.filter(
    (blob) =>
      !isDependencyFixturePath(blob.path) &&
      /(?:^|\/)Cargo\.toml$/iu.test(blob.path)
  );
  const reasons = [];
  if (lockfiles.length > 100 || manifests.length > 500)
    return Object.freeze({
      artifactRecords: Object.freeze([]),
      packageCount: 0,
      reasons: Object.freeze(['cargo-lockfile-count-budget-exceeded'])
    });

  const locksByDirectory = new Set(
    lockfiles.map((blob) => cargoManifestDirectory(blob.path))
  );
  if (lockfiles.length === 0) {
    for (const manifest of manifests)
      reasons.push(`cargo-lockfile-missing:${manifest.path}`);
    return Object.freeze({
      artifactRecords: Object.freeze([]),
      packageCount: 0,
      reasons: Object.freeze([...new Set(reasons)].sort())
    });
  }

  const selected = new Map();
  for (const manifest of manifests) selected.set(manifest.oid, manifest);
  for (const lockfile of lockfiles) {
    selected.set(lockfile.oid, lockfile);
  }
  let selectedBytes = 0;
  let oversizedSource = false;
  for (const blob of selected.values()) {
    if (blob.size > MAX_FILE_BYTES) {
      reasons.push('cargo-lock-or-manifest-file-budget-exceeded');
      oversizedSource = true;
      continue;
    }
    selectedBytes += blob.size;
  }
  if (oversizedSource || selectedBytes > 16 * 1024 * 1024)
    return Object.freeze({
      artifactRecords: Object.freeze([]),
      packageCount: 0,
      reasons: Object.freeze(
        [...new Set([...reasons, 'cargo-lock-source-budget-exceeded'])].sort()
      )
    });

  const contentByOid = catFileBatch(repo, [...selected.keys()]);
  const manifestByPath = new Map();
  for (const manifest of manifests) {
    const bytes = contentByOid.get(manifest.oid);
    if (!bytes || bytes.length > MAX_FILE_BYTES) {
      reasons.push(`cargo-manifest-unavailable:${manifest.path}`);
      continue;
    }
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      const document = parseCargoManifest(text);
      if (!document) throw new Error('manifest-invalid');
      manifestByPath.set(manifest.path, document);
    } catch {
      reasons.push(`cargo-manifest-invalid:${manifest.path}`);
    }
  }

  const workspaceMembersByDirectory = new Map();
  const workspacePackagesByDirectory = new Map();
  let workspaceMemberCount = 0;
  for (const lockfile of lockfiles) {
    const directory = cargoManifestDirectory(lockfile.path);
    const manifestPath = directory ? `${directory}/Cargo.toml` : 'Cargo.toml';
    const workspaceManifest = manifestByPath.get(manifestPath);
    const members = workspaceManifest?.workspace?.members;
    if (members === undefined) continue;
    if (!Array.isArray(members)) {
      reasons.push(`cargo-workspace-members-invalid:${manifestPath}`);
      continue;
    }
    const normalizedMembers = new Set();
    const localPackages = [];
    for (const member of members) {
      workspaceMemberCount++;
      if (workspaceMemberCount > 100_000) {
        reasons.push('cargo-workspace-member-budget-exceeded');
        break;
      }
      if (typeof member !== 'string') {
        reasons.push(`cargo-workspace-member-invalid:${manifestPath}`);
        continue;
      }
      const normalized = path.posix.normalize(member.replaceAll('\\', '/'));
      if (
        normalized === '..' ||
        normalized.startsWith('../') ||
        path.posix.isAbsolute(normalized)
      ) {
        reasons.push(`cargo-workspace-member-escape:${manifestPath}`);
        continue;
      }
      if (normalized.includes('*') || normalized.includes('?')) {
        reasons.push(`cargo-workspace-pattern-unverified:${manifestPath}`);
        continue;
      }
      normalizedMembers.add(normalized);
      const memberManifestPath = path.posix.join(
        directory || '.',
        normalized,
        'Cargo.toml'
      );
      const memberManifest = manifestByPath.get(memberManifestPath);
      if (!memberManifest) {
        reasons.push(`cargo-workspace-member-missing:${manifestPath}`);
        continue;
      }
      const identity = parseCargoManifestIdentity(
        memberManifest,
        workspaceManifest
      );
      if (!identity) {
        reasons.push(`cargo-workspace-member-identity-unknown:${manifestPath}`);
        continue;
      }
      localPackages.push(identity);
    }
    if (workspaceManifest.workspace?.exclude !== undefined)
      reasons.push(`cargo-workspace-excludes-unverified:${manifestPath}`);
    workspaceMembersByDirectory.set(directory, normalizedMembers);
    workspacePackagesByDirectory.set(directory, localPackages);
  }

  for (const manifest of manifests) {
    const memberDirectory = cargoManifestDirectory(manifest.path);
    let directory = memberDirectory;
    let foundLock = false;
    while (!foundLock) {
      if (locksByDirectory.has(directory)) {
        if (directory === memberDirectory) {
          foundLock = true;
          break;
        }
        const relativeMember =
          path.posix.relative(directory || '.', memberDirectory || '.') || '.';
        foundLock =
          workspaceMembersByDirectory.get(directory)?.has(relativeMember) ??
          false;
        break;
      }
      if (!directory) break;
      directory = path.posix.dirname(directory);
      if (directory === '.') directory = '';
    }
    if (!foundLock) reasons.push(`cargo-lockfile-missing:${manifest.path}`);
  }

  const records = new Map();
  let packageCount = 0;
  for (const lockfile of lockfiles) {
    const bytes = contentByOid.get(lockfile.oid);
    if (!bytes || bytes.length > MAX_FILE_BYTES) {
      reasons.push(`cargo-lock-unavailable:${lockfile.path}`);
      continue;
    }
    let lockText;
    try {
      lockText = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      reasons.push(`cargo-lock-invalid:${lockfile.path}`);
      continue;
    }
    const directory = cargoManifestDirectory(lockfile.path);
    const manifestPath = directory ? `${directory}/Cargo.toml` : 'Cargo.toml';
    const rootManifest = manifestByPath.get(manifestPath);
    const rootPackage = parseCargoManifestIdentity(rootManifest);
    const rootPackages = workspacePackagesByDirectory.get(directory) ?? [];
    const inventory = parseCargoLockArtifactInventory(lockText, {
      lockPath: lockfile.path,
      rootPackage,
      rootPackages
    });
    packageCount += inventory.packageCount;
    reasons.push(...inventory.reasons);
    for (const record of inventory.artifactRecords) {
      const key = cargoLockRecordKey(record);
      const prior = records.get(key);
      if (prior && prior.checksum !== record.checksum) {
        records.delete(key);
        reasons.push(`cargo-package-checksum-conflict:${lockfile.path}`);
      } else if (!prior) records.set(key, record);
    }
  }
  return Object.freeze({
    artifactRecords: Object.freeze(
      [...records.values()].sort((left, right) =>
        left.location.localeCompare(right.location)
      )
    ),
    packageCount,
    reasons: Object.freeze([...new Set(reasons)].sort())
  });
}

function inspectGoModuleFiles(repo, commit, tree) {
  const moduleFiles = tree.blobs.filter(
    (blob) =>
      !isDependencyFixturePath(blob.path) && /(?:^|\/)go\.mod$/u.test(blob.path)
  );
  const sums = new Set(
    tree.blobs
      .map((blob) => blob.path)
      .filter(
        (blobPath) =>
          !isDependencyFixturePath(blobPath) &&
          /(?:^|\/)go\.sum$/u.test(blobPath)
      )
  );
  const reasons = [];
  const records = new Map();
  let packageCount = 0;
  if (moduleFiles.length > 32)
    return Object.freeze({
      artifactRecords: Object.freeze([]),
      packageCount: 0,
      reasons: Object.freeze(['go-module-file-count-budget-exceeded'])
    });
  for (const moduleFile of moduleFiles) {
    const directory = path.posix.dirname(moduleFile.path);
    const sumPath = directory === '.' ? 'go.sum' : `${directory}/go.sum`;
    if (!sums.has(sumPath)) {
      reasons.push(`go-sum-missing:${moduleFile.path}`);
      continue;
    }
    const moduleText = readCommitBlob(repo, commit, moduleFile.path);
    const sumText = readCommitBlob(repo, commit, sumPath);
    if (moduleText === undefined || sumText === undefined) {
      reasons.push(`go-module-input-unavailable:${moduleFile.path}`);
      continue;
    }
    const inventory = parseGoModuleArtifactInventory(moduleText, sumText, {
      modulePath: moduleFile.path,
      sumPath
    });
    packageCount += inventory.packageCount;
    reasons.push(...inventory.reasons);
    for (const record of inventory.artifactRecords) {
      const key = goModuleRecordKey(record);
      const prior = records.get(key);
      if (prior && prior.checksum !== record.checksum) {
        records.delete(key);
        reasons.push(`go-module-checksum-conflict:${sumPath}`);
      } else if (!prior) records.set(key, record);
    }
  }
  return Object.freeze({
    artifactRecords: Object.freeze(
      [...records.values()].sort((left, right) =>
        left.location.localeCompare(right.location)
      )
    ),
    packageCount,
    reasons: Object.freeze([...new Set(reasons)].sort())
  });
}

export function inspectDependencyChanges(repo, baseSha, headSha, mergeSha) {
  const reasons = [];
  const headTree = parseTree(
    git(repo, ['ls-tree', '-rz', '--full-tree', headSha])
  );
  const mergeTree = mergeSha
    ? parseTree(git(repo, ['ls-tree', '-rz', '--full-tree', mergeSha]))
    : headTree;
  if (headTree.blobs.some((blob) => /(?:^|\/)\.npmrc$/iu.test(blob.path)))
    reasons.push('unsupported-npm-registry-configuration');
  const unsupportedLockfiles = headTree.blobs
    .map((blob) => blob.path)
    .filter(
      (name) =>
        !isDependencyFixturePath(name) &&
        name !== 'package-lock.json' &&
        /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|deno\.lock|pdm\.lock|uv\.lock|pixi\.lock|conda-lock\.ya?ml)$/iu.test(
          name
        )
    );
  if (unsupportedLockfiles.length > 0)
    reasons.push('unsupported-lockfile-format');
  const unsupportedEcosystemInputs = headTree.blobs.some(
    (blob) =>
      !isDependencyFixturePath(blob.path) &&
      /(?:^|\/)(?:go\.work|go\.work\.sum|vendor\/modules\.txt|\.cargo\/config(?:\.toml)?|uv\.(?:lock|toml)|pdm\.(?:lock|toml)|pixi\.(?:lock|toml)|conda-lock\.ya?ml|environment\.ya?ml|deno\.(?:jsonc?|lock)|poetry\.lock|Pipfile(?:\.lock)?|pyproject\.toml|setup\.(?:py|cfg)|requirements(?:-[^/]+)?\.(?:txt|in)|constraints(?:-[^/]+)?\.txt|Gemfile(?:\.lock)?|[^/]+\.gemspec|\.bundle\/config|composer\.json|composer\.lock|pom\.xml|\.mvn\/(?:extensions\.xml|maven\.config|wrapper\/maven-wrapper\.properties)|gradle\.lockfile|gradle\.properties|libs\.versions\.toml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?)$/iu.test(
        blob.path
      )
  );
  const unsupportedAdditionalEcosystemInputs = headTree.blobs.some(
    (blob) =>
      !isDependencyFixturePath(blob.path) &&
      /(?:^|\/)(?:Package\.resolved|Package\.swift|Podfile(?:\.lock)?|Cartfile(?:\.resolved)?|pubspec\.(?:yaml|lock)|mix\.(?:exs|lock)|packages\.(?:lock\.json|config)|project\.assets\.json|NuGet\.Config|Directory\.(?:Packages|Build)\.(?:props|targets)|global\.json|[^/]+\.(?:csproj|fsproj|vbproj|sln|slnx))$/iu.test(
        blob.path
      )
  );
  if (unsupportedEcosystemInputs || unsupportedAdditionalEcosystemInputs)
    reasons.push('unsupported-dependency-ecosystem-provenance');
  const cargoHead = inspectCargoLockfiles(repo, headSha, headTree);
  const cargoMerge = mergeSha
    ? inspectCargoLockfiles(repo, mergeSha, mergeTree)
    : cargoHead;
  const goHead = inspectGoModuleFiles(repo, headSha, headTree);
  const goMerge = mergeSha
    ? inspectGoModuleFiles(repo, mergeSha, mergeTree)
    : goHead;
  const cargoArtifactRecordsByLocation = new Map();
  for (const artifact of [
    ...cargoHead.artifactRecords,
    ...cargoMerge.artifactRecords
  ])
    cargoArtifactRecordsByLocation.set(artifact.location, artifact);
  reasons.push(...cargoHead.reasons, ...cargoMerge.reasons);
  const goArtifactRecordsByLocation = new Map();
  for (const artifact of [
    ...goHead.artifactRecords,
    ...goMerge.artifactRecords
  ])
    goArtifactRecordsByLocation.set(artifact.location, artifact);
  reasons.push(...goHead.reasons, ...goMerge.reasons);
  const baseLock = readCommitBlob(repo, baseSha, 'package-lock.json');
  const headLock = readCommitBlob(repo, headSha, 'package-lock.json');
  const headManifest = readCommitBlob(repo, headSha, 'package.json');
  if (headManifest) {
    let manifest;
    try {
      manifest = JSON.parse(headManifest);
    } catch {
      reasons.push('package-manifest-invalid');
      manifest = {};
    }
    const hasDependencies = [
      manifest.dependencies,
      manifest.devDependencies,
      manifest.optionalDependencies,
      manifest.peerDependencies
    ].some((group) => group && Object.keys(group).length > 0);
    if (hasDependencies && !headLock) reasons.push('dependency-lock-missing');
  }
  let artifactCount = 0;
  let changedArtifacts = 0;
  let changedArtifactRecords = [];
  let artifactRecords = [];
  let scopedPackages = [];
  if (headLock) {
    const comparison = compareNpmLockfiles(baseLock, headLock, headManifest);
    reasons.push(...comparison.reasons);
    artifactCount = comparison.artifactCount;
    changedArtifacts = comparison.changedArtifacts;
    changedArtifactRecords = comparison.changedArtifactRecords ?? [];
    artifactRecords = comparison.artifactRecords ?? [];
    try {
      scopedPackages = [
        ...new Set(
          [...parseNpmLockInventory(headLock).records.values()]
            .map((record) => record.name.split('/')[0])
            .filter((name) => name.startsWith('@'))
        )
      ].sort();
    } catch {
      // compareNpmLockfiles already reports malformed lock data.
    }
  }
  return Object.freeze({
    reasons: Object.freeze([...new Set(reasons)].sort()),
    artifactCount,
    changedArtifacts,
    changedArtifactRecords: Object.freeze(changedArtifactRecords),
    artifactRecords: Object.freeze(artifactRecords),
    cargoArtifactRecords: Object.freeze(
      [...cargoArtifactRecordsByLocation.values()].sort((left, right) =>
        left.location.localeCompare(right.location)
      )
    ),
    cargoArtifactCount: cargoArtifactRecordsByLocation.size,
    cargoPackageCount: Math.max(
      cargoHead.packageCount,
      cargoMerge.packageCount
    ),
    goArtifactRecords: Object.freeze(
      [...goArtifactRecordsByLocation.values()].sort((left, right) =>
        left.location.localeCompare(right.location)
      )
    ),
    goArtifactCount: goArtifactRecordsByLocation.size,
    goPackageCount: Math.max(goHead.packageCount, goMerge.packageCount),
    scopedPackages: Object.freeze(scopedPackages)
  });
}

export function workflowRunCommands(source, sourcePath = '') {
  let document;
  let workflow;
  try {
    document = parseDocument(source, {
      prettyErrors: false,
      uniqueKeys: true
    });
    if (document.errors.length > 0 || document.warnings.length > 0)
      throw new Error('invalid workflow YAML');
    workflow = document.toJS({ maxAliasCount: 16 });
  } catch {
    throw new Error('Malformed GitHub Actions workflow YAML');
  }
  if (
    !workflow ||
    typeof workflow !== 'object' ||
    Array.isArray(workflow) ||
    !workflow.jobs ||
    typeof workflow.jobs !== 'object' ||
    Array.isArray(workflow.jobs)
  )
    throw new Error('Malformed GitHub Actions workflow structure');

  const commands = [];
  const expressionCache = new Map();
  let expressionScanBytes = 0;
  let runStepCount = 0;
  let environmentCheckCount = 0;
  const inspectExpressions = (value) => {
    const cached = expressionCache.get(value);
    if (cached) return cached;
    expressionScanBytes += Buffer.byteLength(value, 'utf8');
    if (expressionScanBytes > MAX_WORKFLOW_EXPRESSION_SCAN_BYTES)
      throw new Error('Workflow expression analysis exceeds its byte budget');
    const result = inspectWorkflowExpressions(value);
    if (expressionCache.size < MAX_WORKFLOW_EXPRESSION_CACHE_ENTRIES)
      expressionCache.set(value, result);
    return result;
  };
  const parseWorkflowEnv = (value, label) => {
    if (value === undefined) return {};
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Error(`Malformed GitHub Actions ${label} environment`);
    const env = {};
    let count = 0;
    for (const [name, content] of Object.entries(value)) {
      if (++count > MAX_WORKFLOW_ENV_CHECKS)
        throw new Error(
          `GitHub Actions ${label} environment exceeds its budget`
        );
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name))
        throw new Error(`Malformed GitHub Actions ${label} environment`);
      if (
        typeof content !== 'string' &&
        typeof content !== 'number' &&
        typeof content !== 'boolean'
      )
        throw new Error(`Malformed GitHub Actions ${label} environment`);
      env[name] = String(content);
    }
    return env;
  };
  const workflowEnv = parseWorkflowEnv(workflow.env, 'workflow');
  const workflowDefault = workflow.defaults?.run?.['working-directory'];
  if (workflowDefault !== undefined && typeof workflowDefault !== 'string')
    throw new Error('Malformed GitHub Actions default working directory');

  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    if (!job || typeof job !== 'object' || Array.isArray(job))
      throw new Error('Malformed GitHub Actions job structure');
    const steps = job.steps;
    if (steps === undefined) continue;
    if (!Array.isArray(steps))
      throw new Error('Malformed GitHub Actions step list');
    const jobEnv = {
      ...workflowEnv,
      ...parseWorkflowEnv(job.env, 'job')
    };
    const jobDefault = job.defaults?.run?.['working-directory'];
    if (jobDefault !== undefined && typeof jobDefault !== 'string')
      throw new Error('Malformed GitHub Actions default working directory');
    for (const step of steps) {
      if (++runStepCount > MAX_WORKFLOW_RUN_STEPS)
        throw new Error('GitHub Actions run-step count exceeds its budget');
      if (!step || typeof step !== 'object' || Array.isArray(step))
        throw new Error('Malformed GitHub Actions step structure');
      if (step.uses !== undefined && typeof step.uses !== 'string')
        throw new Error('Malformed GitHub Actions action reference');
      if (step.uses?.startsWith('./') || step.uses?.startsWith('.\\'))
        commands.push({
          text: '',
          cwd:
            step['working-directory'] ?? jobDefault ?? workflowDefault ?? '.',
          jobName,
          localActionReference: true
        });
      if (step.run === undefined) continue;
      if (typeof step.run !== 'string')
        throw new Error(
          'GitHub Actions run command is missing or not a scalar'
        );
      const stepDefault = step['working-directory'];
      if (stepDefault !== undefined && typeof stepDefault !== 'string')
        throw new Error('Malformed GitHub Actions step working directory');
      const text = step.run.trim();
      if (!text)
        throw new Error(
          'GitHub Actions run command is missing or not a scalar'
        );
      const stepSpecificEnv = parseWorkflowEnv(step.env, 'step');
      environmentCheckCount +=
        Object.keys(jobEnv).length + Object.keys(stepSpecificEnv).length;
      if (environmentCheckCount > MAX_WORKFLOW_ENV_CHECKS)
        throw new Error(
          'GitHub Actions environment analysis exceeds its budget'
        );
      const stepEnv = { ...jobEnv, ...stepSpecificEnv };
      const effectiveWorkingDirectory =
        stepDefault ?? jobDefault ?? workflowDefault ?? '.';
      const expressionSafety = inspectExpressions(text);
      const hasNpmCommand = npmCommands(text).length > 0;
      const unverifiedNpmEnvironment =
        hasNpmCommand && hasUnsafeNpmConfigEnvironment(stepEnv);
      const dynamicExecutableLookup = Object.keys(stepEnv).some((key) =>
        ['PATH', 'PATHEXT', 'COMSPEC', 'SHELL'].includes(key.toUpperCase())
      );
      const commandIdentifiers = new Set(
        (text.match(/[A-Za-z_][A-Za-z0-9_]*/gu) ?? []).map((name) =>
          name.toLowerCase()
        )
      );
      const launchesChildProcess = commandMayLaunchChildProcess(text);
      const workflowExpression = (expression) => `${'$'}{{ ${expression} }}`;
      const protectedScannerBindings =
        sourcePath === '.github/workflows/stage-a.yml' &&
        path.posix.normalize(
          effectiveWorkingDirectory.replaceAll('\\', '/')
        ) === '.' &&
        text === 'node scripts/stage-a-gate.mjs'
          ? new Map([
              [
                'TOOLIP_STAGE_A_CARGO_SHA256_POLICY',
                workflowExpression('vars.TOOLIP_STAGE_A_CARGO_SHA256_POLICY')
              ],
              ['GITHUB_TOKEN', workflowExpression('github.token')],
              ['STAGE_A_REPOSITORY', workflowExpression('github.repository')],
              [
                'STAGE_A_PR_NUMBER',
                workflowExpression('github.event.pull_request.number')
              ],
              [
                'STAGE_A_PR_AUTHOR',
                workflowExpression('github.event.pull_request.user.login')
              ],
              [
                'STAGE_A_PR_AUTHOR_ASSOCIATION',
                workflowExpression(
                  'github.event.pull_request.author_association'
                )
              ],
              [
                'STAGE_A_PR_HEAD_REPOSITORY',
                workflowExpression(
                  'github.event.pull_request.head.repo.full_name'
                )
              ],
              [
                'STAGE_A_PR_HEAD_IS_FORK',
                workflowExpression('github.event.pull_request.head.repo.fork')
              ],
              [
                'STAGE_A_BASE_REPOSITORY',
                workflowExpression('github.repository')
              ],
              [
                'STAGE_A_BASE_SHA',
                workflowExpression('github.event.pull_request.base.sha')
              ],
              [
                'STAGE_A_HEAD_SHA',
                workflowExpression('github.event.pull_request.head.sha')
              ],
              [
                'STAGE_A_MERGE_SHA_FILE',
                `${workflowExpression('runner.temp')}/toolip-stage-a-current-pr.json`
              ]
            ])
          : undefined;
      let unsafeEnvironmentReference = false;
      let malformedEnvironmentReference = false;
      for (const [name, value] of Object.entries(stepEnv)) {
        const valueSafety = inspectExpressions(value);
        if (!valueSafety.untrusted && !valueSafety.malformed) continue;
        if (protectedScannerBindings?.get(name) === value) continue;
        if (
          !commandIdentifiers.has(name.toLowerCase()) &&
          !launchesChildProcess
        )
          continue;
        unsafeEnvironmentReference = true;
        malformedEnvironmentReference ||= valueSafety.malformed;
      }
      commands.push({
        text,
        cwd: effectiveWorkingDirectory,
        jobName,
        unsafeEnvironmentReference,
        untrustedExpression: expressionSafety.untrusted,
        untrustedEventExpression: expressionSafety.eventDerived,
        unverifiedNpmEnvironment,
        dynamicExecutableLookup,
        malformedExpression:
          expressionSafety.malformed || malformedEnvironmentReference
      });
    }
  }
  return commands;
}

/**
 * Read the JSONC subset used by VS Code tasks: comments and trailing commas.
 * Quoted strings stay byte-for-byte intact; unterminated comments fail closed.
 * O(B) time and O(B) space for B input code units under caller byte limits.
 */
function parseEditorTaskJsonc(source) {
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

function packageManifestNames(texts) {
  const names = new Map();
  for (const [file, source] of texts) {
    if (file !== 'package.json' && !file.endsWith('/package.json')) continue;
    const parsed = JSON.parse(source);
    const name = parsed?.name;
    if (typeof name !== 'string' || !validNpmPackageName(name)) continue;
    if (names.has(name)) names.set(name, undefined);
    else names.set(name, file);
  }
  return names;
}

function workspaceSelectors(command) {
  const selectors = [];
  const patterns = [
    /\b(?:npm|pnpm|yarn)\b[^\r\n]*?\s(?:--workspace(?:=|\s+)|-w\s+)(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/giu,
    /\bpnpm\b[^\r\n]*?\s--filter(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/giu,
    /\byarn\s+workspace\s+(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/giu,
    /\bnpm\s+--prefix(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/giu
  ];
  for (const pattern of patterns)
    for (const match of command.matchAll(pattern)) {
      const selector = match[1] ?? match[2] ?? match[3];
      if (selector) selectors.push(selector);
    }
  return [...new Set(selectors)];
}

function workspacePackageTarget(selector, cwd, packagesByName, texts) {
  if (packagesByName.has(selector)) return packagesByName.get(selector);
  if (
    !selector ||
    selector.includes('$') ||
    selector.includes('*') ||
    selector.includes('?') ||
    selector.startsWith('/') ||
    /^[A-Za-z]:/u.test(selector)
  )
    return undefined;
  const normalized = path.posix.normalize(
    path.posix.join(cwd, selector.replaceAll('\\', '/'))
  );
  if (normalized === '..' || normalized.startsWith('../')) return undefined;
  const target = `${normalized === '.' ? '' : `${normalized}/`}package.json`;
  return texts.has(target) ? target : undefined;
}

/**
 * Discover statically assigned local command targets without evaluating shell.
 * Deliberately ignores ambiguous/reassigned, late and nonliteral values.
 * Each bounded file is walked twice: O(B) time and O(A + R) space for
 * B source units, A assignments and R references.
 */
function staticShellTargets(source) {
  const assignments = new Map();
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
  const resolveTarget = (name, before, visited, depth) => {
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
  const targets = new Set();
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

function localReferences(source, sourcePath, packagesByName, texts) {
  const refs = new Map();
  const commands = [];
  const patterns = [
    /\b(?:import|export)\s+(?:[^'";]*?\s+from\s*)?['"](\.{1,2}\/[^'"]+)['"]/gu,
    /\b(?:require|import)\s*\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/gu,
    /\b(?:load|require)\s+['"](\.{1,2}\/[^'"]+)['"]/gu,
    /\b(?:node|sh|bash|zsh|pwsh|powershell|python(?:3)?|deno|bun|ruby|perl|php)(?:\.exe)?\s+(['"]?)(\.{0,2}\/[^\s'";&|]+|[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*)\1/giu,
    /\bcmd(?:\.exe)?\s+\/(?:c|k)\s+(['"]?)(\.{0,2}\/[^\s'";&|]+|[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*)\1/giu,
    /\bnode(?:\.exe)?\s+(?:--require|-r|--import|--loader)(?:=|\s+)(["']?)(\.{1,2}\/[^\s"';&|]+)\1/giu,
    /\bNODE_OPTIONS\s*=\s*["']?(?:--require|-r|--import|--loader)(?:=|\s+)(["']?)(\.{1,2}\/[^\s"';&|]+)\1/giu
  ];
  for (const pattern of patterns)
    for (const match of source.matchAll(pattern)) {
      const value = match[2] ?? match[1];
      if (value && !value.startsWith('-') && !value.includes(':'))
        refs.set(`${value}\0source`, { value, rootRelative: false });
    }
  const startProcessTarget =
    /\bStart-Process\s+(?:-FilePath\s+)?(?:"([^"\r\n;&|]{1,512})"|'([^'\r\n;&|]{1,512})'|([^\s;&|]+))/giu;
  let startProcessReferences = 0;
  for (const match of source.matchAll(startProcessTarget)) {
    if (startProcessReferences >= MAX_GRAPH_EDGES) {
      refs.set('powershell-unresolved\0budget', {
        value: 'powershell-unresolved-budget',
        rootRelative: true
      });
      break;
    }
    const index = startProcessReferences++;
    const rawTarget = match[1] ?? match[2] ?? match[3] ?? '';
    const target = rawTarget.replaceAll('\\', '/');
    if (target.startsWith('./') || target.startsWith('../')) {
      const resolved = path.posix.normalize(
        path.posix.join(path.posix.dirname(sourcePath), target)
      );
      if (resolved !== '..' && !resolved.startsWith('../'))
        refs.set(`${target}\0powershell`, {
          value: target,
          rootRelative: false
        });
      else
        refs.set(`powershell-unresolved\0${index}`, {
          value: `powershell-unresolved-${index}`,
          rootRelative: true
        });
    } else {
      refs.set(`powershell-unresolved\0${index}`, {
        value: `powershell-unresolved-${index}`,
        rootRelative: true
      });
    }
  }
  const shellAnalysis = staticShellTargets(source);
  for (const target of shellAnalysis.targets)
    refs.set(`${target}\\0static-shell`, {
      value: target,
      rootRelative: false
    });
  if (shellAnalysis.unresolvedShellCommand)
    refs.set('unresolved-shell-command', {
      value: 'unresolved-shell-command',
      rootRelative: true
    });
  if (sourcePath === 'package.json' || sourcePath.endsWith('/package.json')) {
    try {
      const parsed = JSON.parse(source);
      for (const command of Object.values(parsed.scripts ?? {}))
        if (typeof command === 'string')
          commands.push({ text: command, cwd: path.posix.dirname(sourcePath) });
    } catch {
      // scanText reports malformed execution manifests with the exact path.
    }
  } else if (
    sourcePath === '.vscode/tasks.json' ||
    sourcePath.endsWith('/.vscode/tasks.json')
  ) {
    try {
      const parsed = parseEditorTaskJsonc(source);
      const tasks = Array.isArray(parsed.tasks) ? parsed.tasks : [];
      const byLabel = new Map();
      for (const task of tasks) {
        if (typeof task?.label !== 'string') continue;
        const labels = byLabel.get(task.label) ?? [];
        labels.push(task);
        byLabel.set(task.label, labels);
      }
      const queue = tasks.filter(
        (task) =>
          task?.runOptions?.runOn === 'folderOpen' ||
          task?.runOn === 'folderOpen'
      );
      const included = new Set();
      while (queue.length > 0) {
        const task = queue.shift();
        if (!task || included.has(task)) continue;
        included.add(task);
        if (included.size > 10_000)
          throw new Error('task-reference-budget-exceeded');
        const rawCwd =
          typeof task.options?.cwd === 'string' ? task.options.cwd : '.';
        const cwd = path.posix.normalize(rawCwd.replaceAll('\\', '/'));
        if (
          cwd === '..' ||
          cwd.startsWith('../') ||
          cwd.startsWith('/') ||
          /^[A-Za-z]:/u.test(cwd) ||
          cwd.includes('$')
        ) {
          refs.set(`dynamic-task-cwd\0${rawCwd}`, {
            value: `task-cwd:${rawCwd}`,
            rootRelative: true
          });
          continue;
        }
        commands.push({
          text: [
            task.command,
            task.script,
            ...(Array.isArray(task.args) ? task.args : [])
          ]
            .filter((part) => typeof part === 'string')
            .join(' '),
          cwd
        });
        if (task.type === 'npm' && typeof task.script === 'string')
          refs.set(`npm-task\0${cwd}`, {
            value: path.posix.join(cwd, 'package.json'),
            rootRelative: true
          });
        if (task.dependsOn === undefined) continue;
        const dependencies = Array.isArray(task.dependsOn)
          ? task.dependsOn
          : [task.dependsOn];
        for (const dependency of dependencies) {
          const matches = byLabel.get(dependency) ?? [];
          if (typeof dependency !== 'string' || matches.length !== 1) {
            refs.set(`unresolved-task\0${String(dependency)}`, {
              value: `task:${String(dependency)}`,
              rootRelative: true
            });
          } else {
            queue.push(matches[0]);
          }
        }
      }
    } catch {
      // scanText reports malformed execution manifests with the exact path.
    }
  } else if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/iu.test(sourcePath)) {
    commands.push(...workflowRunCommands(source, sourcePath));
  } else {
    commands.push({ text: source, cwd: '.' });
  }
  const processTarget =
    /\b(?:node(?:js)?|deno|bun|sh|bash|zsh|pwsh|powershell|python(?:3)?|ruby|perl|php)(?:\.exe)?\s+(?:(?:--?[^\s]+)\s+)*(?:"([^"\n]+)"|'([^'\n]+)'|([^\s;&|]+))|\bcmd(?:\.exe)?\s+\/(?:c|k)\s+(?:"([^"\n]+)"|'([^'\n]+)'|([^\s;&|]+))/giu;
  for (const command of commands) {
    const cwd = command.cwd.replaceAll('\\', '/');
    const normalizedCwd = path.posix.normalize(cwd);
    if (
      cwd.includes('$') ||
      cwd.includes('${{') ||
      cwd.startsWith('/') ||
      /^[A-Za-z]:/u.test(cwd) ||
      normalizedCwd === '..' ||
      normalizedCwd.startsWith('../')
    ) {
      refs.set(`unresolved-working-directory\0${cwd}`, {
        value: `workflow-cwd:${cwd}`,
        rootRelative: true
      });
      continue;
    }
    for (const match of command.text.matchAll(processTarget)) {
      const value =
        match[1] ?? match[2] ?? match[3] ?? match[4] ?? match[5] ?? match[6];
      if (!value || value.startsWith('-') || value.includes('$')) continue;
      refs.set(`${value}\0${command.cwd}`, {
        value: path.posix.join(normalizedCwd, value),
        rootRelative: true
      });
    }
    if (/\b(?:npm|pnpm|yarn)\s+(?:run|exec)\b/iu.test(command.text)) {
      refs.set('package.json\0root', {
        value: path.posix.join(normalizedCwd, 'package.json'),
        rootRelative: true
      });
    }
    for (const selector of workspaceSelectors(command.text)) {
      const target = workspacePackageTarget(
        selector,
        normalizedCwd,
        packagesByName,
        texts
      );
      refs.set(`workspace\0${selector}\0${command.cwd}`, {
        value: target ?? selector,
        rootRelative: true
      });
    }
    for (const match of command.text.matchAll(
      /\b(?:execFile|execFileSync|spawn|spawnSync)\s*\(\s*['"](?:node|nodejs|deno|bun|sh|bash|pwsh|powershell|python(?:3)?|ruby|perl|php|cmd(?:\.exe)?)['"]\s*,\s*\[?\s*['"]([^'"]+)['"]/giu
    )) {
      const value = match[1];
      if (value && !value.startsWith('-') && !value.includes('$'))
        refs.set(`${value}\0${normalizedCwd}`, {
          value: path.posix.join(normalizedCwd, value),
          rootRelative: true
        });
    }
  }
  return [...refs.values()];
}

function resolveReference(sourcePath, reference, rootRelative = false) {
  if (
    reference.startsWith('/') ||
    reference.startsWith('\\') ||
    /^[A-Za-z]:/u.test(reference) ||
    reference.startsWith('#')
  )
    return undefined;
  const resolved = path.posix.normalize(
    path.posix.join(
      rootRelative ? '' : path.posix.dirname(sourcePath),
      reference
    )
  );
  if (
    resolved === '..' ||
    resolved.startsWith('../') ||
    resolved.startsWith('/')
  )
    return undefined;
  return resolved;
}

function traceChangedEntrypoints(changedPaths, texts, findingPaths) {
  const adjacency = new Map();
  const unresolved = new Map();
  const disguisedTargets = new Map();
  const packagesByName = packageManifestNames(texts);
  for (const candidate of texts.keys()) {
    const extension = path.posix.extname(candidate);
    if (!extension) continue;
    const stem = candidate.slice(0, -extension.length);
    const matches = disguisedTargets.get(stem) ?? [];
    matches.push(candidate);
    disguisedTargets.set(stem, matches);
  }
  let edgeCount = 0;
  for (const [sourcePath, content] of texts) {
    const source = /\.(?:md|mdx|markdown)$/iu.test(sourcePath)
      ? maskMarkdownNonCode(content)
      : content;
    const targets = new Set();
    const unresolvedRefs = new Set();
    for (const reference of localReferences(
      source,
      sourcePath,
      packagesByName,
      texts
    )) {
      const resolved = resolveReference(
        sourcePath,
        reference.value,
        reference.rootRelative
      );
      if (!resolved) continue;
      if (texts.has(resolved)) targets.add(resolved);
      else {
        let found = false;
        for (const suffix of [
          '',
          '.js',
          '.cjs',
          '.mjs',
          '.ts',
          '.tsx',
          '.sh',
          '.py',
          '.rb',
          '.pl',
          '.php',
          '.ps1',
          '.cmd',
          '.bat'
        ])
          if (texts.has(`${resolved}${suffix}`)) {
            targets.add(`${resolved}${suffix}`);
            found = true;
          }
        if (!found) {
          const disguised = disguisedTargets.get(resolved) ?? [];
          if (disguised.length === 1) {
            targets.add(disguised[0]);
            found = true;
          } else if (disguised.length > 1) {
            unresolvedRefs.add(reference.value);
            found = true;
          }
        }
        if (
          !found &&
          (reference.rootRelative || reference.value.startsWith('.'))
        )
          unresolvedRefs.add(reference.value);
      }
    }
    edgeCount += targets.size;
    if (targets.size > 0) adjacency.set(sourcePath, targets);
    if (unresolvedRefs.size > 0) unresolved.set(sourcePath, unresolvedRefs);
    if (edgeCount > MAX_GRAPH_EDGES)
      return { traces: [], incomplete: true, referencedPaths: new Set() };
  }
  const traces = [];
  const referencedPaths = new Set();
  const finish = (incomplete) => ({ traces, incomplete, referencedPaths });
  let traceBytes = 0;
  let work = 0;
  for (const entrypoint of changedPaths) {
    if (!texts.has(entrypoint)) continue;
    if (/\.(?:md|mdx|markdown)$/iu.test(entrypoint)) continue;
    const rawContent = texts.get(entrypoint) ?? '';
    const content = /\.(?:md|mdx|markdown)$/iu.test(entrypoint)
      ? maskMarkdownNonCode(rawContent)
      : rawContent;
    if (
      /\b(?:require|import)\s*\(\s*(?!['"])/u.test(content) ||
      /\b(?:node|nodejs|deno|bun|sh|bash|zsh|pwsh|powershell)\b[\s\S]{0,300}(?:\$\{|\$[A-Za-z_]|process\.env\b)/iu.test(
        content
      ) ||
      /\b(?:node|nodejs|deno|bun)\s+(?:-e|--eval)\b/iu.test(content) ||
      /\b(?:npx|bunx|npm\s+exec|pnpm\s+dlx|yarn\s+dlx)\b/iu.test(content)
    )
      return finish(true);
    const queue = [entrypoint];
    const parents = new Map([[entrypoint, undefined]]);
    let archiveExtractorReached = false;
    let archiveLauncherReached = false;
    for (let cursor = 0; cursor < queue.length; cursor++) {
      if (++work > MAX_TRACE_WORK) return finish(true);
      const current = queue[cursor] ?? '';
      referencedPaths.add(current);
      const currentSource = texts.get(current) ?? '';
      // A changed entrypoint may reach an unchanged extractor and another
      // unchanged file that launches a process. The exact extracted target
      // cannot be established without executing or unpacking the archive;
      // prevent Stage A from approving such a chain as fully inspected.
      archiveExtraction.lastIndex = 0;
      archiveApiExtraction.lastIndex = 0;
      if (
        archiveExtraction.test(currentSource) ||
        archiveApiExtraction.test(currentSource)
      )
        archiveExtractorReached = true;
      if (
        archiveApiExecution.test(currentSource) ||
        /(?:^|[;\n]|&&|\|\|)\s*(?:exec\s+|&\s+)?\.{1,2}[\\/]\S+/mu.test(
          currentSource
        )
      )
        archiveLauncherReached = true;
      if (archiveExtractorReached && archiveLauncherReached)
        return finish(true);
      if (current !== entrypoint && findingPaths.has(current)) {
        const chain = [];
        let node = current;
        while (node !== undefined) {
          chain.push(node);
          node = parents.get(node);
        }
        const trace = chain.reverse().join(' -> ');
        traceBytes += Buffer.byteLength(trace);
        if (traces.length >= MAX_TRACE_COUNT || traceBytes > MAX_TRACE_BYTES)
          return finish(true);
        traces.push(trace);
      }
      if (unresolved.has(current)) return finish(true);
      for (const target of adjacency.get(current) ?? []) {
        if (parents.has(target)) continue;
        parents.set(target, current);
        queue.push(target);
      }
    }
  }
  return {
    traces: [...new Set(traces)].sort(),
    incomplete: false,
    referencedPaths
  };
}

export function scanText(name, text, incompleteReasons = []) {
  const findings = [];
  const dependencyArtifact = name.startsWith('artifact:node_modules/');
  if (
    name === 'package.json' ||
    name.endsWith('/package.json') ||
    name === '.vscode/tasks.json' ||
    name.endsWith('/.vscode/tasks.json')
  ) {
    let parsed;
    try {
      parsed = name.endsWith('/tasks.json')
        ? parseEditorTaskJsonc(text)
        : JSON.parse(text);
    } catch {
      throw new Error(`Malformed execution manifest: ${name}`);
    }
    if (name.endsWith('package.json')) {
      if (
        parsed.scripts !== undefined &&
        (!parsed.scripts ||
          typeof parsed.scripts !== 'object' ||
          Array.isArray(parsed.scripts))
      )
        throw new Error(`Malformed package scripts: ${name}`);
      for (const [script, command] of Object.entries(parsed.scripts ?? {})) {
        if (typeof command !== 'string')
          throw new Error(`Non-text npm script: ${name}#${script}`);
        // Registry-installed dependencies execute these lifecycle hooks during
        // npm install. Their build, test, release and workspace scripts remain
        // inert package metadata and are not part of Stage A's install graph.
        if (
          dependencyArtifact &&
          !['preinstall', 'install', 'postinstall'].includes(script)
        )
          continue;
        if (dangerous.some((pattern) => pattern.test(command)))
          findings.push(`${name}#scripts.${script}`);
        if (hasUnsupportedToolchainExecution(command))
          incompleteReasons.push(
            `unsupported-toolchain-execution:${name}#scripts.${script}`
          );
        if (requiresUnverifiedNpmResolution(command))
          incompleteReasons.push(
            `unverified-npm-resolution:${name}#scripts.${script}`
          );
        if (hasDynamicShellCommandResolution(command))
          incompleteReasons.push(
            `dynamic-command-resolution:${name}#scripts.${script}`
          );
      }
    }
    const tasksFile = name.endsWith('/tasks.json');
    const tasks = tasksFile ? parsed.tasks : undefined;
    if (tasksFile && !Array.isArray(tasks))
      throw new Error(`Malformed editor task list: ${name}`);
    if (tasksFile && tasks.length > 10_000)
      throw new Error(`Editor task count exceeds budget: ${name}`);
    for (const [index, task] of (Array.isArray(tasks) ? tasks : []).entries()) {
      if (!task || typeof task !== 'object' || Array.isArray(task))
        throw new Error(`Malformed editor task ${index}: ${name}`);
      if (
        (task.command !== undefined && typeof task.command !== 'string') ||
        (task.script !== undefined && typeof task.script !== 'string') ||
        (task.args !== undefined &&
          (!Array.isArray(task.args) ||
            task.args.some((part) => typeof part !== 'string'))) ||
        (task.dependsOn !== undefined &&
          !(
            typeof task.dependsOn === 'string' ||
            (Array.isArray(task.dependsOn) &&
              task.dependsOn.every(
                (dependency) => typeof dependency === 'string'
              ))
          )) ||
        (task.options !== undefined &&
          (!task.options ||
            typeof task.options !== 'object' ||
            Array.isArray(task.options) ||
            (task.options.cwd !== undefined &&
              typeof task.options.cwd !== 'string'))) ||
        (task.runOptions !== undefined &&
          (!task.runOptions ||
            typeof task.runOptions !== 'object' ||
            Array.isArray(task.runOptions) ||
            (task.runOptions.runOn !== undefined &&
              !['default', 'folderOpen'].includes(task.runOptions.runOn))))
      )
        throw new Error(`Malformed editor task command: ${name}`);
      if (
        task.options?.env !== undefined &&
        (!task.options.env ||
          typeof task.options.env !== 'object' ||
          Array.isArray(task.options.env) ||
          Object.entries(task.options.env).some(
            ([name, value]) =>
              !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) ||
              typeof value !== 'string'
          ))
      )
        throw new Error(`Malformed editor task environment: ${name}`);
      const command = [
        task.command,
        task.script,
        ...(Array.isArray(task.args) ? task.args : [])
      ]
        .filter((part) => typeof part === 'string')
        .join(' ');
      const folderOpenTask =
        task.runOptions?.runOn === 'folderOpen' || task.runOn === 'folderOpen';
      const taskEnvironment = task.options?.env ?? {};
      if (
        (task.runOptions?.runOn === 'folderOpen' ||
          task.runOn === 'folderOpen') &&
        dangerous.some((pattern) => pattern.test(command))
      )
        findings.push(`${name}#folderOpen`);
      if (
        (task.runOptions?.runOn === 'folderOpen' ||
          task.runOn === 'folderOpen') &&
        hasUnsupportedToolchainExecution(command)
      )
        incompleteReasons.push(
          `unsupported-toolchain-execution:${name}#folderOpen`
        );
      if (
        (task.runOptions?.runOn === 'folderOpen' ||
          task.runOn === 'folderOpen') &&
        requiresUnverifiedNpmResolution(command)
      )
        incompleteReasons.push(`unverified-npm-resolution:${name}#folderOpen`);
      if (
        (task.runOptions?.runOn === 'folderOpen' ||
          task.runOn === 'folderOpen') &&
        hasDynamicShellCommandResolution(command)
      )
        incompleteReasons.push(`dynamic-command-resolution:${name}#folderOpen`);
      if (
        folderOpenTask &&
        Object.keys(taskEnvironment).some((key) =>
          ['PATH', 'PATHEXT', 'COMSPEC', 'SHELL'].includes(key.toUpperCase())
        )
      )
        incompleteReasons.push(`dynamic-command-resolution:${name}#folderOpen`);
      if (folderOpenTask && hasUnsafeNpmConfigEnvironment(taskEnvironment))
        incompleteReasons.push(`unverified-npm-resolution:${name}#folderOpen`);
    }
  }
  // Workflows shipped inside an npm tarball are inert package data in this
  // repository; GitHub Actions never discovers or executes dependency-owned
  // workflow files from node_modules. Continue scanning their contents as
  // ordinary data, but apply workflow execution policy only to repository
  // workflows.
  const embeddedDependencyWorkflow = name.startsWith('artifact:node_modules/');
  if (
    /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/iu.test(name) &&
    !embeddedDependencyWorkflow
  ) {
    const commands = workflowRunCommands(text, name);
    if (commands.some((command) => command.untrustedEventExpression))
      findings.push(`${name}#untrusted-event-shell-interpolation`);
    if (
      commands.some(
        (command) =>
          command.unsafeEnvironmentReference || command.untrustedExpression
      )
    )
      findings.push(`${name}#untrusted-shell-input`);
    if (commands.some((command) => command.malformedExpression))
      incompleteReasons.push(`workflow-expression-coverage-incomplete:${name}`);
    if (commands.some((command) => command.localActionReference))
      incompleteReasons.push(`local-action-execution-unverified:${name}`);
    if (
      commands.some(
        (command) =>
          command.unverifiedNpmEnvironment ||
          requiresUnverifiedNpmResolution(command.text, {
            cwd: command.cwd,
            allowRootCi: true
          })
      )
    )
      incompleteReasons.push(`unverified-npm-resolution:${name}`);
    if (
      commands.some(
        (command) =>
          command.dynamicExecutableLookup ||
          hasDynamicShellCommandResolution(command.text)
      )
    )
      incompleteReasons.push(`dynamic-command-resolution:${name}`);
    if (
      commands.some((command) => hasUnsupportedToolchainExecution(command.text))
    )
      incompleteReasons.push(`unsupported-toolchain-execution:${name}`);
  }
  const packageManifest =
    name === 'package.json' || name.endsWith('/package.json');
  const sourceCode = /\.[cm]?[jt]sx?$/iu.test(name);
  const otherSourceCode = /\.(?:py|go|rs|java|php|rb|sh|bash|ps1|psm1)$/iu.test(
    name
  );
  const markdown = /\.(?:md|mdx|markdown)$/iu.test(name);
  const inertArtifact =
    dependencyArtifact &&
    (markdown ||
      /\.(?:map|html?)$/iu.test(name) ||
      /\.d\.ts$/iu.test(name) ||
      /(?:^|\/)(?:LICENSE|NOTICE)(?:\.[^/]+)?$/iu.test(name) ||
      /(?:^|\/)(?:test|tests|__tests__|fixtures?)\//iu.test(name) ||
      /(?:^|\/)[^/]*\.test\.[cm]?[jt]sx?$/iu.test(name) ||
      /(?:^|\/)configuration_schema\.json$/iu.test(name));
  const nonExecutionExample =
    dependencyArtifact && /(?:^|\/)examples\//iu.test(name);
  const nonExecutableArtifact = inertArtifact || nonExecutionExample;
  const shebang = /^\uFEFF?#!/u.test(text);
  const shellExecutionSource =
    /\.(?:sh|bash|ps1|psm1)$/iu.test(name) ||
    /^\uFEFF?#![^\n]*(?:\b(?:bash|zsh|pwsh|powershell|sh)\b)/iu.test(text);
  const sourceSignature =
    /(?:^|\n)\s*(?:import\s|export\s|(?:const|let|var)\s+\w|(?:async\s+)?function\s+\w|(?:\b(?:curl|wget|eval|exec|source)\b|\.\s+)[^\n]*)/u.test(
      text
    );
  const executableText =
    sourceCode || shebang || (!markdown && sourceSignature);
  if (shellExecutionSource && !nonExecutableArtifact) {
    if (/\bStart-Process\b/iu.test(text))
      incompleteReasons.push(`unresolved-powershell-process:${name}`);
    if (
      requiresUnverifiedNpmResolution(text, {
        cwd: '.',
        allowRootCi: true
      })
    )
      incompleteReasons.push(`unverified-npm-resolution:${name}`);
    if (hasDynamicShellCommandResolution(text))
      incompleteReasons.push(`dynamic-command-resolution:${name}`);
    if (hasUnsupportedToolchainExecution(text))
      incompleteReasons.push(`unsupported-toolchain-execution:${name}`);
  }
  if (path.posix.extname(name) === '' && !nonExecutableArtifact) {
    if (requiresUnverifiedNpmResolution(text))
      incompleteReasons.push(`unverified-npm-resolution:${name}`);
    if (hasDynamicShellCommandResolution(text))
      incompleteReasons.push(`dynamic-command-resolution:${name}`);
    if (hasUnsupportedToolchainExecution(text))
      incompleteReasons.push(`unsupported-toolchain-execution:${name}`);
  }
  const scanContent = executableText
    ? maskJavaScriptNonCode(text)
    : packageManifest
      ? ''
      : markdown
        ? maskMarkdownNonCode(text)
        : text;
  const behaviorContent = executableText
    ? maskJavaScriptNonCode(text, false)
    : text;
  // Dependency archives contain legitimate compiler code generation and
  // parser evaluators (for example Ajv schema compilation and node-gyp's GYP
  // expression parser). Keep generic eval/Function checks for repository code
  // and package lifecycle commands, but in dependency source require the
  // stronger decoded-payload pattern below. Lock integrity, registry signature
  // and provenance checks remain mandatory for every artifact.
  const artifactPython = dependencyArtifact && /\.py$/iu.test(name);
  const contentPatterns = dependencyArtifact
    ? dangerous
        .slice(2)
        .filter((pattern) => !(artifactPython && pattern === dangerous[5]))
    : dangerous;
  for (const pattern of inertArtifact ? [] : contentPatterns)
    if (pattern.test(scanContent)) findings.push(name);
  if (
    executableText &&
    !dependencyArtifact &&
    suspiciousProcessExecution.test(scanContent)
  )
    findings.push(name);
  if (
    (sourceCode || otherSourceCode) &&
    !nonExecutableArtifact &&
    (unsupportedToolchainSpawn.test(sourceCode ? behaviorContent : text) ||
      unsupportedToolchainShellCommand.test(
        sourceCode ? behaviorContent : text
      ))
  )
    incompleteReasons.push(`unsupported-toolchain-execution:${name}`);
  if (
    executableText &&
    !nonExecutableArtifact &&
    hasUnresolvedChildProcessExecution(behaviorContent) &&
    !hasUnsupportedToolchainExecution(behaviorContent)
  )
    incompleteReasons.push(`unresolved-child-process-execution:${name}`);
  if (
    shebang &&
    !nonExecutableArtifact &&
    hasUnsupportedToolchainExecution(scanContent)
  )
    incompleteReasons.push(`unsupported-toolchain-execution:${name}`);
  if (executableText && hasCredentialTransfer(behaviorContent))
    findings.push(`${name}#credential-transfer`);
  if (
    executableText &&
    startupPersistence.test(behaviorContent) &&
    dangerous.some((pattern) => pattern.test(scanContent))
  )
    findings.push(`${name}#payload-persistence`);
  if (executableText && hasArchiveExtractionAndExecution(behaviorContent))
    findings.push(`${name}#archive-execution`);
  return [...new Set(findings)];
}

function inspectChangedWorkflowTrust(name, text) {
  const trustedRootChanged = TRUSTED_WORKFLOW_PATHS.has(name);
  const isWorkflow = /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/iu.test(name);
  if (trustedRootChanged && !isWorkflow)
    return {
      findings: [],
      incompleteReasons: ['workflow-trust-root-change-review']
    };
  if (!isWorkflow) return { findings: [], incompleteReasons: [] };
  const findings = [];
  const incompleteReasons = trustedRootChanged
    ? ['workflow-trust-root-change-review']
    : [];
  for (const match of text.matchAll(/^\s*uses\s*:\s*([^\s#]+)/gimu)) {
    const action = (match[1] ?? '').replace(/^['"]|['"]$/gu, '');
    if (!action) continue;
    if (action.startsWith('./')) {
      incompleteReasons.push('workflow-local-action-review');
      continue;
    }
    if (
      (action.startsWith('docker://') &&
        !/@sha256:[0-9a-f]{64}$/iu.test(action)) ||
      (!action.startsWith('docker://') &&
        !/@[0-9a-f]{40}(?:\s|$)/iu.test(action))
    )
      findings.push(`${name}#unpinned-action`);
  }
  const privilegedTrigger =
    /(^|\n)\s*pull_request_target\s*:/u.test(text) ||
    /(^|\n)\s*on\s*:\s*(?:['"]?pull_request_target['"]?\b|\[[^\]]*\bpull_request_target\b[^\]]*\])/u.test(
      text
    );
  if (privilegedTrigger && name !== '.github/workflows/stage-a.yml')
    findings.push(`${name}#privileged-pull-request-trigger`);

  const lines = text.split(/\r?\n/u);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index] ?? '';
    const header = line.match(/^(\s*)permissions\s*:\s*(.*?)\s*$/iu);
    if (!header) continue;
    const indentation = header[1]?.length ?? 0;
    const inline = (header[2] ?? '').replace(/\s+#.*$/u, '').trim();
    if (/^(?:write-all|\{.*\bwrite\b.*\})$/iu.test(inline)) {
      incompleteReasons.push('workflow-permission-expansion-review');
      continue;
    }
    for (let child = index + 1; child < lines.length; child++) {
      const childLine = lines[child] ?? '';
      if (!childLine.trim() || /^\s*#/u.test(childLine)) continue;
      const childIndentation = childLine.match(/^\s*/u)?.[0].length ?? 0;
      if (childIndentation <= indentation) break;
      if (/^\s*[\w-]+\s*:\s*write\s*(?:#.*)?$/iu.test(childLine)) {
        incompleteReasons.push('workflow-permission-expansion-review');
        break;
      }
    }
  }
  return {
    findings: [...new Set(findings)].sort(),
    incompleteReasons: [...new Set(incompleteReasons)].sort()
  };
}

function maskMarkdownNonCode(source) {
  const mask = (value) => value.replace(/[^\n]/gu, ' ');
  return source
    .replace(/<!--[\s\S]*?-->/gu, mask)
    .replace(/^ {0,3}(`{3,}|~{3,})[^\n]*\n[\s\S]*?^ {0,3}\1[ \t]*$/gmu, mask)
    .replace(/(`+)[^`\n]*\1/gu, mask);
}

/** Scan an immutable tree with F entries and B bounded candidate bytes.
 * Time is O(F log F + B + V + E); additional space is O(F+B+V+E), with
 * explicit file, byte and graph-work limits.
 */
export function scanGitTree(repo, expectedSha, { changedPaths = [] } = {}) {
  if (!/^[0-9a-f]{40}$/iu.test(expectedSha))
    throw new Error('Expected commit SHA is invalid');
  const actual = git(
    repo,
    ['rev-parse', '--verify', `${expectedSha}^{commit}`],
    1024
  )
    .toString('utf8')
    .trim();
  if (actual.toLowerCase() !== expectedSha.toLowerCase())
    throw new Error(
      'Git resolved a different commit than the requested PR SHA'
    );
  const rawTree = git(repo, ['ls-tree', '-rz', '--full-tree', expectedSha]);
  const tree = parseTree(rawTree);
  const linkContents = catFileBatch(repo, [
    ...new Set(tree.links.map((link) => link.oid))
  ]);
  const exactByPath = new Map(tree.blobs.map((blob) => [blob.path, blob]));
  const treePathSet = new Set([
    ...tree.blobs.map((blob) => blob.path),
    ...tree.links.map((link) => link.path)
  ]);
  const sortedTreePaths = tree.blobs.map((blob) => blob.path).sort();
  const sortedLinkPaths = tree.links.map((link) => link.path).sort();
  const blobs = [...tree.blobs];
  const symlinkCoverageIncomplete = [];
  for (const link of tree.links) {
    const rawTarget = linkContents.get(link.oid);
    if (!rawTarget || rawTarget.length > 4096)
      throw new Error(
        `Symlink target is unavailable or oversized: ${link.path}`
      );
    let targetText;
    try {
      targetText = new TextDecoder('utf-8', { fatal: true }).decode(rawTarget);
    } catch {
      throw new Error(`Symlink target is not valid UTF-8: ${link.path}`);
    }
    if (targetText.includes('\0') || !targetText)
      throw new Error(`Symlink target is invalid: ${link.path}`);
    const target = path.posix.normalize(
      path.posix.join(
        path.posix.dirname(link.path),
        gitlinkSafePath(targetText)
      )
    );
    if (target === '..' || target.startsWith('../') || target.startsWith('/'))
      throw new Error(`Symlink escapes repository: ${link.path}`);
    const exact = exactByPath.get(target);
    if (exact) blobs.push({ ...exact, path: link.path });
    else if (target === '.') {
      symlinkCoverageIncomplete.push(`symlink-directory-target:${link.path}`);
    } else if (!hasBlobPrefix(sortedTreePaths, `${target}/`))
      throw new Error(`Symlink target is absent from Git tree: ${link.path}`);
    else {
      for (const targetPath of pathsWithPrefix(sortedTreePaths, `${target}/`)) {
        const source = exactByPath.get(targetPath);
        if (!source) continue;
        const suffix = targetPath.slice(target.length + 1);
        blobs.push({ ...source, path: `${link.path}/${suffix}` });
        if (blobs.length > MAX_FILES)
          throw new Error(
            'Symlink expansion exceeds Stage A file-count budget'
          );
      }
      if (hasBlobPrefix(sortedLinkPaths, `${target}/`))
        symlinkCoverageIncomplete.push(`nested-symlink-target:${link.path}`);
    }
  }
  if (blobs.length > MAX_FILES)
    throw new Error(
      'Git tree including symlinks exceeds Stage A file-count budget'
    );
  blobs.sort((a, b) => a.path.localeCompare(b.path));
  const digest = createHash('sha256');
  const findings = [];
  const incompleteReasons = [
    ...symlinkCoverageIncomplete,
    ...changedPaths
      .filter(
        (name) => TRUSTED_WORKFLOW_PATHS.has(name) && !treePathSet.has(name)
      )
      .map((name) => `workflow-trust-root-removal-review:${name}`),
    ...changedPaths
      .filter((name) =>
        ARCHIVE_EXTENSIONS.has(path.posix.extname(name).toLowerCase())
      )
      .map((name) => `unsupported-archive:${name}`)
  ];
  const workflowReviewReasons = [];
  const texts = new Map();
  const changedSet = new Set(changedPaths);
  for (const blob of tree.blobs) {
    const ext = path.posix.extname(blob.path).toLowerCase();
    if (changedSet.has(blob.path) && EXECUTABLE_BINARY_EXTENSIONS.has(ext))
      incompleteReasons.push(`unsupported-executable-binary:${blob.path}`);
  }
  let totalBytes = 0;
  let scanned = 0;
  for (const entry of [...tree.blobs, ...tree.links].sort((a, b) =>
    a.path.localeCompare(b.path)
  ))
    digest
      .update(entry.mode)
      .update('\0')
      .update(entry.path)
      .update('\0')
      .update(entry.oid)
      .update('\n');
  const candidates = blobs.filter(
    (blob) =>
      isTextCandidate(blob.path) ||
      (changedSet.has(blob.path) &&
        BINARY_EXTENSIONS.has(path.posix.extname(blob.path).toLowerCase()))
  );
  const contentByOid = catFileBatch(repo, [
    ...new Set(candidates.map((blob) => blob.oid))
  ]);
  for (const blob of candidates) {
    const bytes = contentByOid.get(blob.oid);
    if (!bytes) throw new Error(`Git blob content is missing: ${blob.path}`);
    totalBytes += bytes.length;
    if (bytes.length > MAX_FILE_BYTES)
      throw new Error(`Stage A file exceeds byte budget: ${blob.path}`);
    if (totalBytes > MAX_TOTAL_BYTES)
      throw new Error('Git tree exceeds Stage A total-byte budget');
    if (bytes.includes(0)) {
      const ext = path.posix.extname(blob.path).toLowerCase();
      if (
        changedSet.has(blob.path) &&
        (hasExecutableMagic(bytes) ||
          blob.mode === '100755' ||
          (!BINARY_EXTENSIONS.has(ext) && !ARCHIVE_EXTENSIONS.has(ext)))
      )
        incompleteReasons.push(`unsupported-binary:${blob.path}`);
      continue;
    }
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      throw new Error(`Text candidate is not valid UTF-8: ${blob.path}`);
    }
    scanned++;
    texts.set(blob.path, text);
    findings.push(...scanText(blob.path, text, incompleteReasons));
    if (changedSet.has(blob.path)) {
      const workflow = inspectChangedWorkflowTrust(blob.path, text);
      findings.push(...workflow.findings);
      workflowReviewReasons.push(...workflow.incompleteReasons);
    }
  }
  // A changed script can reach an UNCHANGED executable disguised as .bin or
  // another known-binary suffix. Initial candidate filtering must not make
  // such an execution-chain target invisible. Inspect referenced, immutable
  // Git object bytes as inert data, never execute or unpack the object.
  const withheldBinaryPaths = new Map(
    blobs
      .filter(
        (blob) =>
          BINARY_EXTENSIONS.has(path.posix.extname(blob.path).toLowerCase()) &&
          !texts.has(blob.path)
      )
      .map((blob) => [blob.path, blob])
  );
  const withheldBinaryStems = new Map();
  for (const name of withheldBinaryPaths.keys()) {
    const extension = path.posix.extname(name);
    if (!extension) continue;
    const stem = name.slice(0, -extension.length);
    const paths = withheldBinaryStems.get(stem) ?? [];
    paths.push(name);
    withheldBinaryStems.set(stem, paths);
  }
  const seenReferences = new Set(
    changedPaths.filter((name) => texts.has(name))
  );
  const packageNamesForReferences = packageManifestNames(texts);
  let frontier = [...seenReferences];
  let additionalCandidates = 0;
  let traversalWork = 0;
  for (
    let depth = 0;
    depth < MAX_REFERENCED_BINARY_GRAPH_DEPTH && frontier.length > 0;
    depth++
  ) {
    const next = [];
    const missing = new Map();
    for (const sourcePath of frontier) {
      if (++traversalWork > MAX_TRACE_WORK) {
        incompleteReasons.push('referenced-executable-graph-budget-exceeded');
        break;
      }
      const source = texts.get(sourcePath);
      if (source === undefined) continue;
      for (const reference of localReferences(
        source,
        sourcePath,
        packageNamesForReferences,
        texts
      )) {
        if (++traversalWork > MAX_TRACE_WORK) {
          incompleteReasons.push('referenced-executable-graph-budget-exceeded');
          break;
        }
        const resolved = resolveReference(
          sourcePath,
          reference.value,
          reference.rootRelative
        );
        if (!resolved) continue;
        let target = resolved;
        if (!texts.has(target) && !withheldBinaryPaths.has(target)) {
          const aliases = withheldBinaryStems.get(resolved) ?? [];
          if (aliases.length > 1) {
            incompleteReasons.push(`ambiguous-disguised-reference:${resolved}`);
            continue;
          }
          if (aliases.length !== 1) continue;
          target = aliases[0];
        }
        if (seenReferences.has(target)) continue;
        seenReferences.add(target);
        if (texts.has(target)) {
          next.push(target);
          continue;
        }
        const blob = withheldBinaryPaths.get(target);
        if (!blob) continue;
        if (++additionalCandidates > MAX_REFERENCED_BINARY_CANDIDATES) {
          incompleteReasons.push('referenced-binary-file-budget-exceeded');
          continue;
        }
        missing.set(target, blob);
      }
    }
    if (traversalWork > MAX_TRACE_WORK) break;
    if (missing.size > 0) {
      // Batch Git reads by object SHA instead of starting a process per
      // reference. This is O(reachable edges + bytes), bounded by 256 probes,
      // 16 layers, and the shared Stage A total-byte budget.
      const rawByOid = catFileBatch(repo, [
        ...new Set([...missing.values()].map((blob) => blob.oid))
      ]);
      for (const [target, blob] of missing) {
        const bytes = rawByOid.get(blob.oid);
        if (!bytes || bytes.length > MAX_FILE_BYTES) {
          incompleteReasons.push(
            `referenced-binary-content-uninspected:${target}`
          );
          continue;
        }
        totalBytes += bytes.length;
        if (totalBytes > MAX_TOTAL_BYTES)
          throw new Error('Referenced Git objects exceed Stage A byte budget');
        if (bytes.includes(0)) {
          incompleteReasons.push(
            `referenced-binary-content-uninspected:${target}`
          );
          continue;
        }
        let text;
        try {
          text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch {
          incompleteReasons.push(
            `referenced-binary-content-uninspected:${target}`
          );
          continue;
        }
        texts.set(target, text);
        scanned++;
        findings.push(...scanText(target, text, incompleteReasons));
        next.push(target);
      }
    }
    frontier = next;
  }
  if (frontier.length > 0)
    incompleteReasons.push('referenced-executable-graph-depth-exceeded');
  const findingPaths = new Set(
    findings.map((finding) => finding.split('#', 1)[0] ?? finding)
  );
  const executionChains = traceChangedEntrypoints(
    changedPaths,
    texts,
    findingPaths
  );
  findings.push(
    ...executionChains.traces.map((chain) => `execution-chain:${chain}`)
  );
  if (executionChains.incomplete)
    incompleteReasons.push('execution-reference-coverage-incomplete');
  const relevantPaths = new Set(changedPaths);
  for (const target of executionChains.referencedPaths ?? [])
    relevantPaths.add(target);
  for (const chain of executionChains.traces)
    for (const target of chain.split(' -> ')) relevantPaths.add(target);
  const pathIsRelevant = (value) =>
    relevantPaths.has(value) ||
    relevantPaths.has(value.split('#', 1)[0] ?? value);
  const candidateFindings = findings.filter((finding) => {
    if (changedPaths.length === 0) return true;
    if (finding.startsWith('execution-chain:')) return true;
    return pathIsRelevant(finding.split('#', 1)[0] ?? finding);
  });
  const candidateIncomplete = incompleteReasons.filter((reason) => {
    if (changedPaths.length === 0) return true;
    if (reason.startsWith('referenced-binary-content-uninspected:'))
      return true;
    const separator = reason.indexOf(':');
    if (separator < 0) return true;
    const detail = reason.slice(separator + 1);
    return !/[./\\]/u.test(detail) || pathIsRelevant(detail);
  });
  const stableFindings = [...new Set(candidateFindings)].sort();
  const stableIncomplete = [...new Set(candidateIncomplete)].sort();
  stableIncomplete.push(...new Set(workflowReviewReasons));
  stableIncomplete.sort();
  return Object.freeze({
    status: stableFindings.length
      ? 'blocked'
      : stableIncomplete.length
        ? 'incomplete'
        : 'approved',
    commit: expectedSha,
    inputSha256: digest.digest('hex'),
    files: tree.blobs.length + tree.links.length,
    textFiles: scanned,
    bytes: totalBytes,
    coverage: Object.freeze({
      files: tree.blobs.length + tree.links.length,
      textFiles: scanned,
      bytes: totalBytes,
      changedFiles: changedPaths.length
    }),
    changedFiles: Object.freeze([...changedPaths].sort()),
    reasonCodes: Object.freeze(
      [
        ...(stableFindings.length ? ['suspicious-execution-content'] : []),
        ...stableIncomplete.map((reason) => reason.split(':', 1)[0] ?? reason)
      ].sort()
    ),
    incompleteReasons: Object.freeze(stableIncomplete),
    findings: Object.freeze(stableFindings)
  });
}

export function verifyPullRequestMergeParents(
  repo,
  mergeSha,
  baseSha,
  headSha
) {
  const parents = git(
    repo,
    ['rev-list', '--parents', '-n', '1', mergeSha],
    2048
  )
    .toString('ascii')
    .trim()
    .split(/\s+/u)
    .slice(1);
  if (!parents.includes(baseSha) || !parents.includes(headSha))
    throw new Error(
      'GitHub merge commit does not contain the event base and head commits'
    );
}

const githubAuthorAssociations = new Set([
  'COLLABORATOR',
  'CONTRIBUTOR',
  'FIRST_TIMER',
  'FIRST_TIME_CONTRIBUTOR',
  'MANNEQUIN',
  'MEMBER',
  'NONE',
  'OWNER'
]);

/** Emits contextual review requirements without treating fork authors as malicious. */
export function stageAAuthorshipReviewSignals(input) {
  const association =
    typeof input.authorAssociation === 'string'
      ? input.authorAssociation.toUpperCase()
      : '';
  const headRepository = input.headRepository;
  const headIsFork = input.headIsFork;
  const baseRepository = input.baseRepository;
  const signals = [];
  const incompleteReasons = [];

  if (!githubAuthorAssociations.has(association)) {
    incompleteReasons.push('pull-request-author-context-unavailable');
  } else if (
    [
      'CONTRIBUTOR',
      'FIRST_TIMER',
      'FIRST_TIME_CONTRIBUTOR',
      'MANNEQUIN',
      'NONE'
    ].includes(association)
  ) {
    signals.push(
      Object.freeze({
        id: 'external-author-association',
        association,
        reviewRequired: true,
        message:
          'GitHub classifies this author as an external contributor; require independent maintainer review before merge.'
      })
    );
  }

  const validRepository = (value) =>
    typeof value === 'string' &&
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(value) &&
    !value.split('/').some((segment) => segment === '.' || segment === '..');
  if (
    !validRepository(headRepository) ||
    !validRepository(baseRepository) ||
    typeof headIsFork !== 'boolean'
  ) {
    incompleteReasons.push('pull-request-repository-context-unavailable');
  } else if (headIsFork) {
    signals.push(
      Object.freeze({
        id: 'fork-head-repository',
        headRepository,
        reviewRequired: true,
        message:
          'This pull request head is a fork; keep execution read-only and require independent maintainer review before merge.'
      })
    );
  } else if (headRepository !== baseRepository) {
    incompleteReasons.push('pull-request-repository-context-inconsistent');
  }

  const commitVerification = input.headCommitVerification;
  if (
    !commitVerification ||
    typeof commitVerification.verified !== 'boolean' ||
    typeof commitVerification.reason !== 'string'
  ) {
    incompleteReasons.push('head-commit-verification-unavailable');
  } else if (!commitVerification.verified) {
    signals.push(
      Object.freeze({
        id: 'head-commit-signature-unverified',
        verificationReason: commitVerification.reason,
        reviewRequired: true,
        message:
          'GitHub could not verify the pull request head commit signature; check repository signature policy and document owner review before merge.'
      })
    );
  }

  return Object.freeze({
    signals: Object.freeze(signals),
    incompleteReasons: Object.freeze([...new Set(incompleteReasons)].sort())
  });
}

/** Reads only GitHub's bounded signature-verification summary for the exact head SHA. */
export async function fetchHeadCommitVerification({
  repository,
  headSha,
  token,
  fetchImpl = globalThis.fetch
}) {
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository ?? '') ||
    repository
      .split('/')
      .some((segment) => segment === '.' || segment === '..') ||
    !/^[0-9a-f]{40}$/iu.test(headSha ?? '') ||
    typeof token !== 'string' ||
    token.length < 20
  )
    throw new Error('head-commit-verification-input-invalid');
  const response = await fetchImpl(
    `https://api.github.com/repos/${repository}/commits/${headSha}`,
    {
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': '2022-11-28'
      }
    }
  );
  if (
    response.status !== 200 ||
    (response.url && new URL(response.url).origin !== 'https://api.github.com')
  )
    throw new Error('head-commit-verification-provider-unavailable');
  let payload;
  try {
    payload = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(
        await boundedResponseBytes(response, 256 * 1024)
      )
    );
  } catch {
    throw new Error('head-commit-verification-response-invalid');
  }
  const verification = payload?.commit?.verification;
  if (
    payload?.sha?.toLowerCase() !== headSha.toLowerCase() ||
    !verification ||
    typeof verification.verified !== 'boolean' ||
    (verification.reason !== null && typeof verification.reason !== 'string')
  )
    throw new Error('head-commit-verification-response-invalid');
  const acceptedReasons = new Set([
    'valid',
    'unsigned',
    'unknown_key',
    'bad_email',
    'unverified_email',
    'expired_key',
    'not_signing_key',
    'malformed_signature',
    'invalid',
    'gpgverify_unavailable',
    'gpgverify_error',
    'unknown_signature_type',
    'no_user',
    'wont_sign'
  ]);
  const reason = verification.reason;
  if (
    (verification.verified && reason !== 'valid') ||
    (!verification.verified && reason === 'valid')
  )
    throw new Error('head-commit-verification-response-invalid');
  return Object.freeze({
    verified: verification.verified,
    reason:
      typeof reason === 'string' && acceptedReasons.has(reason)
        ? reason
        : verification.verified
          ? 'valid'
          : 'unknown'
  });
}

/** Fetch a pull ref into an isolated bare object database; never check out PR files. */
export async function scanGithubPullRequest({
  repository,
  number,
  baseSha,
  headSha,
  mergeSha,
  token,
  fetchImpl = globalThis.fetch,
  dependencyAuditDirectory,
  allowedPublicScopes = [],
  pullRequestAuthor,
  pullRequestAuthorAssociation,
  pullRequestHeadRepository,
  pullRequestHeadIsFork,
  pullRequestBaseRepository,
  headCommitVerification
}) {
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository ?? '') ||
    repository.split('/').some((segment) => segment === '.' || segment === '..')
  )
    throw new Error('GitHub repository identity is invalid');
  if (!Number.isSafeInteger(Number(number)) || Number(number) < 1)
    throw new Error('Pull request number is invalid');
  if (
    [baseSha, headSha, mergeSha].some(
      (sha) => !/^[0-9a-f]{40}$/iu.test(sha ?? '')
    )
  )
    throw new Error('Base, head, and merge commit SHAs are required');
  if (typeof token !== 'string' || token.length < 20)
    throw new Error('Read-only GitHub token is unavailable');
  if (
    !Array.isArray(allowedPublicScopes) ||
    allowedPublicScopes.some((scope) => !/^@[A-Za-z0-9._-]+$/u.test(scope))
  )
    throw new Error('Trusted public npm scope policy is invalid');
  const bare = await mkdtemp(path.join(os.tmpdir(), 'toolip-stage-a-objects-'));
  try {
    execFileSync('git', ['--no-replace-objects', 'init', '--bare', bare], {
      encoding: 'buffer',
      maxBuffer: 4096,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10_000,
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_TERMINAL_PROMPT: '0'
      }
    });
    const auth = `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`;
    const remote = `https://github.com/${repository}.git`;
    execFileSync(
      'git',
      [
        '--no-replace-objects',
        '--git-dir',
        bare,
        'fetch',
        '--no-tags',
        '--no-recurse-submodules',
        '--depth=2',
        remote,
        `refs/pull/${Number(number)}/merge`
      ],
      {
        encoding: 'buffer',
        maxBuffer: 16 * 1024 * 1024,
        timeout: 120_000,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          PATH: process.env.PATH,
          HOME: process.env.HOME,
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_TERMINAL_PROMPT: '0',
          GIT_CONFIG_COUNT: '1',
          GIT_CONFIG_KEY_0: 'http.extraheader',
          GIT_CONFIG_VALUE_0: auth
        }
      }
    );
    const fetched = git(
      bare,
      ['rev-parse', '--verify', 'FETCH_HEAD^{commit}'],
      1024
    )
      .toString('utf8')
      .trim();
    if (fetched.toLowerCase() !== mergeSha.toLowerCase())
      throw new Error(
        'PR merge moved or GitHub returned a different commit than the event SHA'
      );
    verifyPullRequestMergeParents(bare, mergeSha, baseSha, headSha);
    const changedPaths = listPullRequestChanges(bare, baseSha, headSha);
    const dependency = inspectDependencyChanges(
      bare,
      baseSha,
      headSha,
      mergeSha
    );
    const dependencyInspectionStartedAt = Date.now();
    // Inspect the complete locked install graph before Stage B. Unchanged lock
    // identities are not a trusted content cache: runners may download and
    // execute their lifecycle hooks again on every run.
    const dependencyArtifacts = await inspectNpmArtifacts(
      dependency.artifactRecords,
      { fetchImpl, allowedPublicScopes }
    );
    const npmInspectionDurationMs = Math.min(
      MAX_ARTIFACT_DEADLINE_MS,
      Date.now() - dependencyInspectionStartedAt
    );
    const cargoArtifacts = await inspectCargoArtifacts(
      dependency.cargoArtifactRecords,
      {
        fetchImpl,
        deadlineMs: MAX_ARTIFACT_DEADLINE_MS - npmInspectionDurationMs,
        maxCount: Math.max(
          0,
          MAX_ARTIFACT_COUNT - dependency.artifactRecords.length
        ),
        maxTotalBytes: Math.max(
          0,
          MAX_ARTIFACT_TOTAL_BYTES - dependencyArtifacts.coverage.bytes
        ),
        maxTotalNetworkBytes: Math.max(
          0,
          MAX_ARTIFACT_TOTAL_BYTES - dependencyArtifacts.coverage.networkBytes
        ),
        maxFiles: Math.max(
          0,
          MAX_ARTIFACT_FILES - dependencyArtifacts.coverage.files
        )
      }
    );
    const goArtifacts = await inspectGoArtifacts(dependency.goArtifactRecords, {
      fetchImpl,
      deadlineMs: Math.max(
        0,
        MAX_ARTIFACT_DEADLINE_MS - (Date.now() - dependencyInspectionStartedAt)
      ),
      maxCount: Math.max(
        0,
        MAX_ARTIFACT_COUNT -
          dependency.artifactRecords.length -
          dependency.cargoArtifactRecords.length
      ),
      maxTotalBytes: Math.max(
        0,
        MAX_ARTIFACT_TOTAL_BYTES -
          dependencyArtifacts.coverage.bytes -
          cargoArtifacts.coverage.bytes
      ),
      maxTotalNetworkBytes: Math.max(
        0,
        MAX_ARTIFACT_TOTAL_BYTES -
          dependencyArtifacts.coverage.networkBytes -
          cargoArtifacts.coverage.networkBytes
      ),
      maxFiles: Math.max(
        0,
        MAX_ARTIFACT_FILES -
          dependencyArtifacts.coverage.files -
          cargoArtifacts.coverage.files
      )
    });
    const cargoArtifactPolicy = verifyCargoArtifactPolicy(
      dependency.cargoArtifactRecords,
      process.env.TOOLIP_STAGE_A_CARGO_SHA256_POLICY
    );
    const head = scanGitTree(bare, headSha, { changedPaths });
    const merged = scanGitTree(bare, mergeSha, { changedPaths });
    let findings = [
      ...new Set([
        ...head.findings,
        ...merged.findings,
        ...dependencyArtifacts.findings,
        ...cargoArtifacts.findings,
        ...goArtifacts.findings
      ])
    ].sort();
    const appliedExceptions = [];
    const exceptionReviewReasons = [];
    let exceptionPolicySha256 = null;
    let exceptionPolicyText;
    try {
      exceptionPolicyText = readCommitBlob(
        bare,
        baseSha,
        '.toolip/stage-a-exceptions.json'
      );
    } catch {
      exceptionReviewReasons.push('stage-a-exception-policy-invalid');
    }
    if (exceptionPolicyText !== undefined) {
      exceptionPolicySha256 = createHash('sha256')
        .update(exceptionPolicyText)
        .digest('hex');
      const policy = parseStageAExceptionPolicy(exceptionPolicyText);
      if (policy.invalid) {
        exceptionReviewReasons.push('stage-a-exception-policy-invalid');
      } else {
        const candidateFindingIds = new Set(
          [
            ...head.findings,
            ...merged.findings,
            ...dependencyArtifacts.findings,
            ...cargoArtifacts.findings,
            ...goArtifacts.findings
          ].map((finding) => stageAFindingRecord(finding).id)
        );
        const candidateIncompleteReasons = [
          ...head.incompleteReasons,
          ...merged.incompleteReasons,
          ...dependency.reasons,
          ...dependencyArtifacts.reasons,
          ...cargoArtifacts.reasons,
          ...goArtifacts.reasons,
          ...cargoArtifactPolicy.reasons
        ];
        const candidateIncompleteReasonSet = new Set(
          candidateIncompleteReasons
        );
        const candidateReasonCodes = new Set(
          candidateIncompleteReasons.map(
            (reason) => reason.split(':', 1)[0] ?? reason
          )
        );
        const matchingExceptions = matchingStageAExceptions(
          policy.entries,
          head.inputSha256,
          candidateFindingIds,
          candidateIncompleteReasons
        );
        if (matchingExceptions.length > 0) {
          let independentApproval;
          if (matchingExceptions.some((entry) => !entry.ownerAttestation)) {
            try {
              if (!pullRequestAuthor)
                throw new Error('pull-request-author-unavailable');
              independentApproval = await fetchCurrentMaintainerApproval({
                repository,
                number: Number(number),
                headSha,
                pullRequestAuthor,
                token,
                fetchImpl
              });
            } catch {
              exceptionReviewReasons.push(
                'stage-a-exception-review-unavailable'
              );
            }
            if (!independentApproval && exceptionReviewReasons.length === 0)
              exceptionReviewReasons.push('stage-a-exception-review-required');
          }
          const suppressedFindings = new Set();
          const suppressedReasons = new Set();
          const suppressedExactReasons = new Set();
          for (const entry of matchingExceptions) {
            const approval = entry.ownerAttestation
              ? currentOwnerAttestation(entry, {
                  repository,
                  headSha,
                  headInputSha256: head.inputSha256,
                  incompleteReasons: candidateIncompleteReasonSet,
                  verifiedArtifactSha512ByLocation:
                    dependencyArtifacts.verifiedArtifactSha512ByLocation
                })
              : independentApproval;
            if (!approval) {
              if (entry.ownerAttestation)
                exceptionReviewReasons.push(
                  'stage-a-owner-attestation-invalid'
                );
              continue;
            }
            const findingApplies = Boolean(
              entry.findingId && candidateFindingIds.has(entry.findingId)
            );
            const reasonApplies = Boolean(
              entry.reasonCode &&
              (entry.exactReason
                ? candidateIncompleteReasonSet.has(entry.exactReason)
                : candidateReasonCodes.has(entry.reasonCode))
            );
            if (!findingApplies && !reasonApplies) continue;
            if (entry.findingId) suppressedFindings.add(entry.findingId);
            if (entry.exactReason)
              suppressedExactReasons.add(entry.exactReason);
            else if (entry.reasonCode) suppressedReasons.add(entry.reasonCode);
            appliedExceptions.push(
              Object.freeze({
                id: entry.id,
                ...(entry.findingId ? { findingId: entry.findingId } : {}),
                ...(entry.reasonCode ? { reasonCode: entry.reasonCode } : {}),
                ...(entry.exactReason
                  ? {
                      exactReason: entry.exactReason,
                      ownerAttestation: entry.ownerAttestation
                    }
                  : {}),
                headInputSha256: entry.headInputSha256,
                expiresAt: entry.expiresAt,
                reviewer: approval.login,
                reviewedAt: approval.submittedAt,
                reviewedCommit: approval.commitId
              })
            );
          }
          findings = findings.filter(
            (finding) =>
              !suppressedFindings.has(stageAFindingRecord(finding).id)
          );
          if (suppressedReasons.size > 0 || suppressedExactReasons.size > 0)
            exceptionReviewReasons.push(
              ...[...suppressedReasons].map(
                (reason) => 'stage-a-exception-applied:' + reason
              ),
              ...[...suppressedExactReasons].map(
                (reason) => 'stage-a-exception-applied:' + reason
              )
            );
        }
      }
    }
    const dependencyIncompleteReasons = dependency.reasons.filter(
      (reason) => reason !== 'dependency-artifact-uninspected'
    );
    if (
      dependency.artifactCount > dependencyArtifacts.coverage.checked &&
      !dependencyIncompleteReasons.includes('dependency-artifact-uninspected')
    )
      dependencyIncompleteReasons.push('dependency-artifact-uninspected');
    let reviewedPolicyText;
    let reviewedPolicyReadError = false;
    try {
      reviewedPolicyText = readCommitBlob(
        bare,
        baseSha,
        '.toolip/stage-a-reviewed-dependencies.json'
      );
    } catch {
      reviewedPolicyReadError = true;
    }
    const reviewedPolicy = parseStageAReviewedDependencyPolicy(
      reviewedPolicyReadError ? '{' : reviewedPolicyText
    );
    const baseLock = readCommitBlob(bare, baseSha, 'package-lock.json');
    const headLock = readCommitBlob(bare, headSha, 'package-lock.json');
    const sha256 = (content) =>
      typeof content === 'string'
        ? createHash('sha256').update(content, 'utf8').digest('hex')
        : null;
    const reviewedDependencies = applyStageAReviewedDependencyPolicy({
      parsed: reviewedPolicy,
      repository,
      currentLockfileSha256: sha256(headLock),
      baseLockfileSha256: sha256(baseLock),
      changedArtifactCount: dependency.changedArtifacts,
      reasons: dependencyArtifacts.reasons,
      verifiedArtifactSha512ByLocation:
        dependencyArtifacts.verifiedArtifactSha512ByLocation,
      verifiedBinaryFilesByLocation:
        dependencyArtifacts.verifiedBinaryFilesByLocation
    });
    const suppressedExceptionReasonCodes = new Set(
      appliedExceptions
        .filter((entry) => !entry.exactReason)
        .map((entry) => entry.reasonCode)
        .filter((code) => typeof code === 'string')
    );
    const suppressedExceptionExactReasons = new Set(
      appliedExceptions
        .map((entry) => entry.exactReason)
        .filter((reason) => typeof reason === 'string')
    );
    const incompleteReasons = [
      ...new Set([
        ...head.incompleteReasons,
        ...merged.incompleteReasons,
        ...dependencyIncompleteReasons,
        ...cargoArtifacts.reasons,
        ...goArtifacts.reasons,
        ...cargoArtifactPolicy.reasons,
        ...(dependency.cargoArtifactCount > cargoArtifacts.coverage.checked
          ? ['cargo-dependency-artifact-uninspected']
          : []),
        ...(dependency.goArtifactCount > goArtifacts.coverage.checked
          ? ['go-dependency-artifact-uninspected']
          : []),
        ...(dependency.scopedPackages.some(
          (scope) => !allowedPublicScopes.includes(scope)
        )
          ? ['scoped-registry-signature-audit-withheld']
          : []),
        ...reviewedDependencies.remainingReasons,
        ...exceptionReviewReasons.filter(
          (reason) =>
            reason.startsWith('stage-a-exception-') &&
            !reason.startsWith('stage-a-exception-applied:')
        )
      ])
    ]
      .filter(
        (reason) =>
          !suppressedExceptionExactReasons.has(reason) &&
          !suppressedExceptionReasonCodes.has(reason.split(':', 1)[0] ?? reason)
      )
      .sort();
    let exactHeadCommitVerification = headCommitVerification;
    if (!exactHeadCommitVerification) {
      try {
        exactHeadCommitVerification = await fetchHeadCommitVerification({
          repository,
          headSha,
          token,
          fetchImpl
        });
      } catch {
        exactHeadCommitVerification = undefined;
      }
    }
    const authorship = stageAAuthorshipReviewSignals({
      authorAssociation: pullRequestAuthorAssociation,
      headRepository: pullRequestHeadRepository,
      headIsFork: pullRequestHeadIsFork,
      baseRepository: pullRequestBaseRepository ?? repository,
      headCommitVerification: exactHeadCommitVerification
    });
    const combinedIncompleteReasons = [
      ...new Set([...incompleteReasons, ...authorship.incompleteReasons])
    ].sort();
    const combinedReasonCodes = [
      ...new Set([
        ...(findings.length ? ['suspicious-execution-content'] : []),
        ...combinedIncompleteReasons.map(
          (reason) => reason.split(':', 1)[0] ?? reason
        )
      ])
    ].sort();
    const result = Object.freeze({
      ...merged,
      status: findings.length
        ? 'blocked'
        : combinedIncompleteReasons.length
          ? 'incomplete'
          : 'approved',
      findings: Object.freeze(findings),
      reasonCodes: Object.freeze(combinedReasonCodes),
      incompleteReasons: Object.freeze(combinedIncompleteReasons),
      reviewSignals: authorship.signals,
      exceptionPolicySha256,
      appliedExceptions: Object.freeze(appliedExceptions),
      reviewedDependencyReasons: reviewedDependencies.reviewedReasons,
      reviewedDependencyBinaryFiles: reviewedDependencies.reviewedBinaryFiles,
      reviewedDependencyBaselineSha256: reviewedDependencies.baselineSha256,
      verifiedArtifactSha512ByLocation:
        dependencyArtifacts.verifiedArtifactSha512ByLocation,
      verifiedArtifactSha256ByLocation: Object.freeze({
        ...cargoArtifacts.verifiedArtifactSha256ByLocation,
        ...goArtifacts.verifiedArtifactSha256ByLocation
      }),
      cargoArtifactPolicySha256: cargoArtifactPolicy.policySha256,
      coverage: Object.freeze({
        changedFiles: changedPaths.length,
        head: head.coverage,
        merge: merged.coverage,
        dependencyArtifactsChecked: dependencyArtifacts.coverage.checked,
        dependencyArtifactsChanged: dependency.changedArtifacts,
        dependencyArtifactCount: dependency.artifactCount,
        dependencyArtifactFiles: dependencyArtifacts.coverage.files,
        dependencyArtifactBytes: dependencyArtifacts.coverage.bytes,
        dependencyArtifactNetworkBytes:
          dependencyArtifacts.coverage.networkBytes,
        dependencyArtifactBinaryFiles: dependencyArtifacts.coverage.binaryFiles,
        reviewedDependencyBinaryFiles: reviewedDependencies.reviewedBinaryFiles,
        nonNpmDependencyArtifactsChecked:
          cargoArtifacts.coverage.checked + goArtifacts.coverage.checked,
        nonNpmDependencyArtifactCount:
          dependency.cargoArtifactCount + dependency.goArtifactCount,
        cargoDependencyArtifactCount: dependency.cargoArtifactCount,
        goDependencyArtifactCount: dependency.goArtifactCount,
        nonNpmDependencyArtifactFiles:
          cargoArtifacts.coverage.files + goArtifacts.coverage.files,
        nonNpmDependencyArtifactBytes:
          cargoArtifacts.coverage.bytes + goArtifacts.coverage.bytes,
        nonNpmDependencyArtifactNetworkBytes:
          cargoArtifacts.coverage.networkBytes +
          goArtifacts.coverage.networkBytes,
        nonNpmDependencyArtifactBinaryFiles:
          cargoArtifacts.coverage.binaryFiles +
          goArtifacts.coverage.binaryFiles,
        headCommitSignatureStatus: exactHeadCommitVerification
          ? exactHeadCommitVerification.verified
            ? 'verified'
            : 'unverified'
          : 'unavailable'
      }),
      headFiles: head.files,
      headTextFiles: head.textFiles,
      headBytes: head.bytes,
      headInputSha256: head.inputSha256,
      headCommit: headSha,
      mergeCommit: mergeSha,
      baseCommit: baseSha,
      changedFiles: Object.freeze(changedPaths)
    });
    if (
      result.status === 'approved' &&
      dependencyAuditDirectory &&
      dependency.artifactCount > 0
    ) {
      const manifest = readCommitBlob(bare, headSha, 'package.json');
      const lock = readCommitBlob(bare, headSha, 'package-lock.json');
      if (!manifest || !lock)
        throw new Error(
          'Verified dependency signature audit input is unavailable'
        );
      await mkdir(dependencyAuditDirectory, { mode: 0o700 });
      await writeFile(
        path.join(dependencyAuditDirectory, 'package.json'),
        manifest,
        {
          flag: 'wx',
          mode: 0o600
        }
      );
      await writeFile(
        path.join(dependencyAuditDirectory, 'package-lock.json'),
        lock,
        {
          flag: 'wx',
          mode: 0o600
        }
      );
    }
    return result;
  } finally {
    await rm(bare, { recursive: true, force: true });
  }
}

const stageARules = Object.freeze({
  'TLP-STAGEA-EXECUTION-CHAIN': {
    name: 'Potentially unsafe execution chain',
    description:
      'A changed entrypoint reaches content flagged by the bounded static scanner.'
  },
  'TLP-STAGEA-ENTRYPOINT': {
    name: 'Potentially unsafe execution entrypoint',
    description:
      'An execution manifest contains a command pattern that needs review.'
  },
  'TLP-STAGEA-SUSPICIOUS-CONTENT': {
    name: 'Suspicious static content pattern',
    description:
      'A bounded non-executing content scan found a suspicious pattern.'
  },
  'TLP-STAGEA-UNPINNED-ACTION': {
    name: 'Mutable GitHub Action reference',
    description:
      'A changed workflow references an action without an immutable commit SHA.'
  },
  'TLP-STAGEA-PRIVILEGED-WORKFLOW': {
    name: 'Privileged pull request workflow trigger',
    description:
      'A changed workflow requests pull_request_target execution outside the trusted Stage A workflow.'
  },
  'TLP-STAGEA-UNTRUSTED-SHELL-INPUT': {
    name: 'Untrusted workflow data in shell commands',
    description:
      'A GitHub Actions shell command consumes an untrusted expression or an environment value derived from one.'
  },
  'TLP-STAGEA-GATE-ERROR': {
    name: 'Stage A gate did not complete',
    description:
      'The trusted pre-execution scanner could not establish complete coverage.'
  }
});

function redactStageAValue(value) {
  return value
    .replace(
      /([a-z][a-z0-9+.-]*:\/\/)(?=[^\s/?#]*@)[^\s/?#]*@/giu,
      '$1[redacted]@'
    )
    .replace(
      /([?&](?:token|access_token|refresh_token|api[_-]?key|password|secret|signature|sig)=)[^&#\s]+/giu,
      '$1[redacted]'
    )
    .replace(
      /\b((?:NPM|GITHUB|GITLAB|AWS|AZURE|API|ACCESS|AUTH|JWT)[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)|(?:token|api[_-]?key|password|passphrase|passwd|pwd|client_secret|secret))\s*([=:])\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
      '$1$2[redacted]'
    )
    .replace(
      /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b/gu,
      '[redacted-token]'
    );
}

function stageAFindingRecord(finding) {
  const isTrace = finding.startsWith('execution-chain:');
  const rawTrace = isTrace ? finding.slice('execution-chain:'.length) : '';
  const firstPath = isTrace
    ? (rawTrace.split(' -> ', 1)[0] ?? 'unknown')
    : (finding.split('#', 1)[0] ?? 'unknown');
  const ruleId = isTrace
    ? 'TLP-STAGEA-EXECUTION-CHAIN'
    : /#unpinned-action\b/u.test(finding)
      ? 'TLP-STAGEA-UNPINNED-ACTION'
      : /#privileged-pull-request-trigger\b/u.test(finding)
        ? 'TLP-STAGEA-PRIVILEGED-WORKFLOW'
        : /#untrusted-shell-input\b/u.test(finding)
          ? 'TLP-STAGEA-UNTRUSTED-SHELL-INPUT'
          : /#(?:scripts\.|folderOpen)/u.test(finding)
            ? 'TLP-STAGEA-ENTRYPOINT'
            : 'TLP-STAGEA-SUSPICIOUS-CONTENT';
  const location = redactStageAValue(firstPath).slice(0, 512);
  const trace = isTrace
    ? redactStageAValue(rawTrace).slice(0, 2_048)
    : undefined;
  const message = isTrace
    ? 'A changed entrypoint reaches a suspicious local target; review the short trace in SARIF.'
    : ruleId === 'TLP-STAGEA-UNPINNED-ACTION'
      ? 'A changed workflow references an action by a mutable tag or branch; pin and review the exact commit before execution.'
      : ruleId === 'TLP-STAGEA-PRIVILEGED-WORKFLOW'
        ? 'A changed workflow uses pull_request_target outside the protected Stage A gate; this can expose write-scoped credentials to untrusted pull request data.'
        : ruleId === 'TLP-STAGEA-UNTRUSTED-SHELL-INPUT'
          ? 'A workflow shell command consumes untrusted event, secret, token or action-output data; pass validated values through a non-shell interface or review the workflow before execution.'
          : ruleId === 'TLP-STAGEA-ENTRYPOINT'
            ? 'An execution entrypoint contains a suspicious command pattern; review it before running project scripts.'
            : 'A bounded static scan found suspicious content; the scanner did not execute the content.';
  const id = createHash('sha256')
    .update(`${ruleId}\0${location}\0${trace ?? ''}`)
    .digest('hex');
  return Object.freeze({
    id,
    ruleId,
    location,
    message,
    ...(trace ? { trace } : {})
  });
}

function sarifUri(relativePath) {
  return relativePath
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

export function buildStageAFeedback(result) {
  const findings = (result.findings ?? [])
    .map(stageAFindingRecord)
    .sort((left, right) => left.id.localeCompare(right.id));
  if (
    (result.status === 'error' || result.status === 'incomplete') &&
    findings.length === 0
  ) {
    const location = 'Stage A trusted scanner';
    findings.push(
      Object.freeze({
        id: createHash('sha256')
          .update(`TLP-STAGEA-GATE-ERROR\0${location}`)
          .digest('hex'),
        ruleId: 'TLP-STAGEA-GATE-ERROR',
        location,
        message:
          'The trusted Stage A scanner could not establish complete coverage; approval was withheld.'
      })
    );
  }
  const ruleIds = [
    ...new Set(findings.map((finding) => finding.ruleId))
  ].sort();
  const ruleIndex = new Map(ruleIds.map((ruleId, index) => [ruleId, index]));
  const sarif = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Toolip Stage A',
            informationUri: 'https://www.zivoralabs.xyz/open-source/toolip/',
            rules: ruleIds.map((id) => ({
              id,
              name: stageARules[id]?.name ?? 'Stage A gate result',
              shortDescription: {
                text: stageARules[id]?.name ?? 'Stage A gate result'
              },
              fullDescription: {
                text: stageARules[id]?.description ?? 'Stage A gate result.'
              },
              defaultConfiguration: { level: 'error' }
            }))
          }
        },
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          ruleIndex: ruleIndex.get(finding.ruleId),
          level: 'error',
          message: {
            text: `${finding.message}${finding.trace ? ` Trace: ${finding.trace}` : ''}`
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: sarifUri(finding.location) }
              }
            }
          ],
          partialFingerprints: { primaryLocationLineHash: finding.id }
        })),
        properties: {
          status: result.status,
          reasonCodes: [...new Set(result.reasonCodes ?? [])].sort(),
          coverage: result.coverage ?? {},
          reviewSignals: result.reviewSignals ?? []
        }
      }
    ]
  };
  return Object.freeze({ findings, sarif });
}

function escapeWorkflowCommand(value) {
  return value
    .replaceAll('%', '%25')
    .replaceAll('\r', '%0D')
    .replaceAll('\n', '%0A')
    .replaceAll(':', '%3A')
    .replaceAll(',', '%2C');
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export async function writeStageAFeedback(result, environment = process.env) {
  const feedback = buildStageAFeedback(result);
  const runnerTemp = environment.RUNNER_TEMP;
  if (runnerTemp)
    await writeFile(
      path.join(runnerTemp, 'stage-a-results.sarif'),
      `${JSON.stringify(feedback.sarif, null, 2)}\n`,
      { mode: 0o600 }
    );
  const summary = environment.GITHUB_STEP_SUMMARY;
  if (summary) {
    const coverage = JSON.stringify(result.coverage ?? {});
    const lines = [
      '## Toolip Stage A pre-execution scan',
      '',
      `Scanner result: **${escapeHtml(result.status)}**`,
      `Coverage: <code>${escapeHtml(coverage.slice(0, 2_000))}</code>`,
      `Reason codes: <code>${escapeHtml((result.reasonCodes ?? []).join(', ') || 'none')}</code>`,
      `Findings: ${feedback.findings.length}`,
      `Authorship review signals: ${(result.reviewSignals ?? []).length}`,
      ...(result.reviewSignals ?? []).map(
        (signal) =>
          `- **${escapeHtml(signal.id)}** ${escapeHtml(signal.message)}`
      ),
      `Reviewed exceptions applied: ${(result.appliedExceptions ?? []).length}`,
      ...(result.appliedExceptions ?? []).map(
        (entry) =>
          `- Exception <code>${escapeHtml(entry.id)}</code> reviewed by <code>${escapeHtml(entry.reviewer)}</code> for head <code>${escapeHtml(entry.reviewedCommit)}</code>, expires ${escapeHtml(entry.expiresAt)}`
      ),
      '',
      ...feedback.findings
        .slice(0, 100)
        .map(
          (finding) =>
            `- **${finding.ruleId}** <code>${finding.id.slice(0, 16)}</code> at <code>${escapeHtml(finding.location)}</code>${finding.trace ? ` — <code>${escapeHtml(finding.trace)}</code>` : ''}`
        ),
      '',
      'This content result is not final approval: the required scripts-disabled install/signature check and approval artifact must also succeed.'
    ];
    await appendFile(summary, `${lines.join('\n')}\n`);
  }
  if (environment.GITHUB_ACTIONS === 'true') {
    for (const signal of result.reviewSignals ?? [])
      process.stdout.write(
        `::warning title=Toolip Stage A review::${escapeWorkflowCommand(signal.message)}\n`
      );
    for (const finding of feedback.findings.slice(0, 100))
      process.stdout.write(
        `::error title=${escapeWorkflowCommand(finding.ruleId)}::${escapeWorkflowCommand(`${finding.id.slice(0, 16)}: ${finding.message}`)}\n`
      );
    if (result.status !== 'approved' && feedback.findings.length === 0)
      process.stdout.write(
        `::error title=Toolip Stage A incomplete::Approval withheld; reason codes: ${escapeWorkflowCommand((result.reasonCodes ?? []).join(', ') || 'stage-a-incomplete')}\n`
      );
  }
  return feedback;
}

async function main() {
  const args = process.argv.slice(2);
  let [repository, number, baseSha, headSha, mergeSha] = args.length
    ? args
    : [
        process.env.STAGE_A_REPOSITORY,
        process.env.STAGE_A_PR_NUMBER,
        process.env.STAGE_A_BASE_SHA,
        process.env.STAGE_A_HEAD_SHA,
        process.env.STAGE_A_MERGE_SHA
      ];
  if (!args.length && process.env.STAGE_A_MERGE_SHA_FILE) {
    const mergeIdentityText = await readFile(
      process.env.STAGE_A_MERGE_SHA_FILE,
      'utf8'
    );
    if (Buffer.byteLength(mergeIdentityText, 'utf8') > 4096)
      throw new Error('Current pull request merge identity exceeds its budget');
    const mergeIdentity = JSON.parse(mergeIdentityText);
    if (
      mergeIdentity?.baseSha !== baseSha ||
      mergeIdentity?.headSha !== headSha ||
      !/^[0-9a-f]{40}$/iu.test(mergeIdentity?.mergeSha ?? '')
    )
      throw new Error(
        'Current pull request merge identity is stale or invalid'
      );
    mergeSha = mergeIdentity.mergeSha;
  }
  if (!repository || !number || !baseSha || !headSha || !mergeSha)
    throw new Error(
      'Usage: node scripts/stage-a-gate.mjs <owner/repo> <pull-request-number> <base-sha> <head-sha> <merge-sha>'
    );
  const expectedScannerSha = process.env.TOOLIP_STAGE_A_SHA256;
  if (!/^[0-9a-f]{64}$/iu.test(expectedScannerSha ?? ''))
    throw new Error('Trusted workflow did not pin the Stage A scanner digest');
  const scannerSha = await trustedScannerDigest();
  if (scannerSha !== expectedScannerSha.toLowerCase())
    throw new Error(
      'Stage A scanner digest differs from the protected workflow pin'
    );
  const result = await scanGithubPullRequest({
    repository,
    number: Number(number),
    baseSha,
    headSha,
    mergeSha,
    token: process.env.GITHUB_TOKEN,
    pullRequestAuthor: process.env.STAGE_A_PR_AUTHOR,
    pullRequestAuthorAssociation: process.env.STAGE_A_PR_AUTHOR_ASSOCIATION,
    pullRequestHeadRepository: process.env.STAGE_A_PR_HEAD_REPOSITORY,
    pullRequestHeadIsFork:
      process.env.STAGE_A_PR_HEAD_IS_FORK === 'true'
        ? true
        : process.env.STAGE_A_PR_HEAD_IS_FORK === 'false'
          ? false
          : undefined,
    pullRequestBaseRepository:
      process.env.STAGE_A_BASE_REPOSITORY ?? process.env.STAGE_A_REPOSITORY,
    allowedPublicScopes: (process.env.TOOLIP_STAGE_A_PUBLIC_SCOPES ?? '')
      .split(',')
      .map((scope) => scope.trim())
      .filter(Boolean),
    dependencyAuditDirectory: path.join(
      process.env.RUNNER_TEMP ?? os.tmpdir(),
      'toolip-stage-a-dependency-audit'
    )
  });
  const feedback = await writeStageAFeedback(result);
  process.stdout.write(
    `${JSON.stringify({
      scannerSha256: scannerSha,
      ...result,
      findings: feedback.findings
    })}\n`
  );
  if (result.status === 'approved') {
    const runnerTemp = process.env.RUNNER_TEMP;
    if (!runnerTemp || !process.env.GITHUB_OUTPUT)
      throw new Error('Trusted runner temporary directory is unavailable');
    await appendFile(
      process.env.GITHUB_OUTPUT,
      `status=approved\ndependency_audit_required=${result.coverage.dependencyArtifactCount > 0}\n`
    );
    await writeFile(
      path.join(runnerTemp, 'stage-a-scan.json'),
      `${JSON.stringify({ scannerSha256: scannerSha, ...result })}\n`,
      { flag: 'wx', mode: 0o600 }
    );
  }
  if (result.status !== 'approved') process.exitCode = 1;
}

export { trustedScannerDigest };

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch(async (error) => {
    const message = (
      error instanceof Error ? error.message : 'unknown scan failure'
    )
      .replace(/[\r\n\t]+/gu, ' ')
      .slice(0, 512);
    await writeStageAFeedback({
      status: 'error',
      reasonCodes: ['stage-a-error'],
      findings: []
    }).catch(() => undefined);
    process.stdout.write(
      `${JSON.stringify({ status: 'error', reasonCodes: ['stage-a-error'], message: redactStageAValue(message) })}\n`
    );
    process.exitCode = 2;
  });
}
