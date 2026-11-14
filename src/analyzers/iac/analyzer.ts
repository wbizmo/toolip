import {
  LineCounter,
  isAlias,
  isMap,
  isPair,
  isScalar,
  isSeq,
  parseAllDocuments,
  type parseDocument
} from 'yaml';
import path from 'node:path';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import { coverageOf } from '../../contracts/analysis.js';
import type { Finding, FindingSeverity } from '../../contracts/finding.js';
import { createScannerContext } from '../../core/scanner-context.js';
import type { ScannerContext } from '../../core/scanner-context.js';
import type { ProjectFile } from '../../core/file-walker.js';
import { bindSourceProvenance } from '../../core/source-provenance.js';
import {
  TextFileReader,
  type TextFileReadResult
} from '../../core/text-file-reader.js';

type FlatYamlValue = {
  path: string[];
  value: unknown;
  line: number;
  documentIndex: number;
};
type IaCRule = {
  id: string;
  title: string;
  severity: FindingSeverity;
  message: string;
  remediation: string;
  cwe?: string;
  securityControl: string;
};

const rules: Record<string, IaCRule> = {
  'TLP-IAC-K8S-001': {
    id: 'TLP-IAC-K8S-001',
    title: 'Privileged Kubernetes container',
    severity: 'critical',
    message: 'A Kubernetes container enables privileged mode.',
    remediation:
      'Remove privileged mode and grant only the container capabilities it needs.',
    cwe: 'CWE-250',
    securityControl: 'least-privilege'
  },
  'TLP-IAC-K8S-002': {
    id: 'TLP-IAC-K8S-002',
    title: 'Kubernetes workload permits privilege escalation',
    severity: 'high',
    message: 'A container allows privilege escalation.',
    remediation:
      'Set allowPrivilegeEscalation to false and review required capabilities.',
    cwe: 'CWE-269',
    securityControl: 'least-privilege'
  },
  'TLP-IAC-K8S-003': {
    id: 'TLP-IAC-K8S-003',
    title: 'Kubernetes workload uses host networking',
    severity: 'high',
    message: 'The workload shares the host network namespace.',
    remediation:
      'Disable host networking unless the workload has a documented requirement.',
    cwe: 'CWE-668',
    securityControl: 'workload-isolation'
  },
  'TLP-IAC-K8S-004': {
    id: 'TLP-IAC-K8S-004',
    title: 'Kubernetes workload mounts a host path',
    severity: 'high',
    message: 'A pod mounts a path from the host filesystem.',
    remediation:
      'Use a scoped persistent volume or another isolated storage mechanism.',
    cwe: 'CWE-552',
    securityControl: 'workload-isolation'
  },
  'TLP-IAC-K8S-005': {
    id: 'TLP-IAC-K8S-005',
    title: 'Kubernetes container does not require a non-root user',
    severity: 'medium',
    message:
      'A container has no applicable runAsNonRoot: true security context.',
    remediation:
      'Set runAsNonRoot: true at the container or pod level and pin an appropriate numeric runAsUser when needed.',
    cwe: 'CWE-250',
    securityControl: 'least-privilege'
  },
  'TLP-IAC-GHA-001': {
    id: 'TLP-IAC-GHA-001',
    title: 'GitHub Actions permission grants write access',
    severity: 'high',
    message: 'The workflow grants a write permission to its token.',
    remediation:
      'Grant only the minimum required permission at the job that needs it.',
    cwe: 'CWE-250',
    securityControl: 'least-privilege'
  },
  'TLP-IAC-GHA-002': {
    id: 'TLP-IAC-GHA-002',
    title: 'GitHub Action is not pinned to an immutable revision',
    severity: 'medium',
    message:
      'A third-party action reference is not pinned to a full commit SHA.',
    remediation:
      'Pin the action to a reviewed full commit SHA and update it deliberately.',
    cwe: 'CWE-829',
    securityControl: 'immutable-dependencies'
  },
  'TLP-IAC-GHA-003': {
    id: 'TLP-IAC-GHA-003',
    title: 'Untrusted pull request data reaches a shell command',
    severity: 'high',
    message:
      'A shell command interpolates attacker-controlled pull request text.',
    remediation:
      'Pass untrusted values through environment variables and validate them before use.',
    cwe: 'CWE-78',
    securityControl: 'untrusted-input'
  },
  'TLP-IAC-TF-001': {
    id: 'TLP-IAC-TF-001',
    title: 'Terraform storage permits public access',
    severity: 'high',
    message: 'Terraform configures a storage bucket with public access.',
    remediation:
      'Block public ACLs and policies unless public access is explicitly required.',
    cwe: 'CWE-732',
    securityControl: 'public-access'
  },
  'TLP-IAC-TF-002': {
    id: 'TLP-IAC-TF-002',
    title: 'Terraform security group exposes administration ports',
    severity: 'high',
    message: 'An ingress rule exposes SSH or RDP to the public internet.',
    remediation:
      'Restrict administrative ingress to approved private networks.',
    cwe: 'CWE-284',
    securityControl: 'network-boundary'
  },
  'TLP-IAC-TF-003': {
    id: 'TLP-IAC-TF-003',
    title: 'Terraform IAM policy grants wildcard actions and resources',
    severity: 'critical',
    message: 'An IAM policy grants Action * over Resource *.',
    remediation:
      'Limit actions and resources to the exact operations and ARNs required.',
    cwe: 'CWE-250',
    securityControl: 'least-privilege'
  },
  'TLP-IAC-TF-004': {
    id: 'TLP-IAC-TF-004',
    title: 'Terraform ingress is open to the public internet',
    severity: 'high',
    message: 'A network ingress rule accepts traffic from 0.0.0.0/0 or ::/0.',
    remediation:
      'Restrict ingress to an approved CIDR range or private network.',
    cwe: 'CWE-284',
    securityControl: 'network-boundary'
  },
  'TLP-IAC-TF-005': {
    id: 'TLP-IAC-TF-005',
    title: 'Terraform bucket policy grants public access',
    severity: 'high',
    message: 'An S3 bucket policy allows access to every principal.',
    remediation:
      'Restrict the policy principal to the required account or workload identities.',
    cwe: 'CWE-732',
    securityControl: 'public-access'
  },
  'TLP-IAC-TF-006': {
    id: 'TLP-IAC-TF-006',
    title: 'Terraform cloud storage allows public access',
    severity: 'high',
    message:
      'A cloud storage configuration permits anonymous or public identities.',
    remediation:
      'Remove public principals and disable anonymous object access unless the data is intentionally public.',
    cwe: 'CWE-732',
    securityControl: 'public-access'
  },
  'TLP-IAC-TF-007': {
    id: 'TLP-IAC-TF-007',
    title: 'Terraform storage permits anonymous blob access',
    severity: 'medium',
    message:
      'An Azure storage account permits containers to enable anonymous public blob access.',
    remediation:
      'Set allow_nested_items_to_be_public to false unless anonymous blob access is required and reviewed.',
    cwe: 'CWE-732',
    securityControl: 'public-access'
  }
};

function finding(
  rule: IaCRule,
  file: string,
  line: number,
  fingerprint: string
): Finding {
  return {
    id: `${rule.id}:${file}:${line}`,
    ruleId: rule.id,
    title: rule.title,
    category: 'infrastructure',
    severity: rule.severity,
    confidence: 'medium',
    message: rule.message,
    source: 'infrastructure-as-code',
    location: { file, line, column: 1 },
    evidence: [{ summary: rule.message, fingerprint }],
    remediation: { summary: rule.remediation },
    metadata: {
      ...(rule.cwe ? { cwe: rule.cwe } : {}),
      securityControl: rule.securityControl
    }
  };
}

function flattenYaml(
  document: ReturnType<typeof parseDocument>,
  lineCounter: LineCounter,
  documentIndex: number
): FlatYamlValue[] {
  const pending: Array<{ node: unknown; path: string[] }> = [
    { node: document.contents, path: [] }
  ];
  const values: FlatYamlValue[] = [];
  let visited = 0;
  let aliases = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current?.node) continue;
    visited++;
    if (visited > 100_000 || current.path.length > 100) {
      throw new Error('YAML structure exceeds the analysis budget');
    }
    if (isMap(current.node)) {
      for (const item of current.node.items) {
        if (!isPair(item)) continue;
        const key = isScalar(item.key)
          ? String(item.key.value)
          : '[complex-key]';
        pending.push({ node: item.value, path: [...current.path, key] });
      }
    } else if (isSeq(current.node)) {
      for (let index = current.node.items.length - 1; index >= 0; index--) {
        pending.push({
          node: current.node.items[index],
          path: [...current.path, String(index)]
        });
      }
    } else if (isAlias(current.node)) {
      aliases++;
      if (aliases > 1_000)
        throw new Error('YAML alias expansion exceeds the analysis budget');
      const resolved = current.node.resolve(document);
      if (resolved) pending.push({ node: resolved, path: current.path });
    } else if (isScalar(current.node)) {
      const offset = current.node.range?.[0] ?? 0;
      values.push({
        path: current.path,
        value: current.node.value,
        line: lineCounter.linePos(offset).line,
        documentIndex
      });
    }
  }
  return values;
}

function pathEnds(value: FlatYamlValue, suffix: string): boolean {
  return value.path.at(-1)?.toLowerCase() === suffix.toLowerCase();
}

function scanYaml(file: string, source: string): Finding[] {
  const lineCounter = new LineCounter();
  const documents = parseAllDocuments(source, {
    uniqueKeys: true,
    prettyErrors: false,
    version: '1.2',
    lineCounter
  });
  const normalizedPath = file.replaceAll('\\', '/').toLowerCase();
  const isWorkflow = /(^|\/)\.github\/workflows\//.test(normalizedPath);
  const findings: Finding[] = [];
  const byRuleLine = new Set<string>();
  for (const [documentIndex, document] of documents.entries()) {
    if (document.errors.length) throw new Error('malformed YAML document');
    const values = flattenYaml(
      document as unknown as ReturnType<typeof parseDocument>,
      lineCounter,
      documentIndex
    );
    const isKubernetes =
      /(^|\/)(k8s|kubernetes|manifests)(\/|$)/i.test(normalizedPath) ||
      values.some((item) => pathEnds(item, 'apiVersion'));
    const add = (ruleId: string, item: FlatYamlValue) => {
      const rule = rules[ruleId];
      if (!rule) return;
      const identity = `${ruleId}:${item.line}`;
      if (byRuleLine.has(identity)) return;
      byRuleLine.add(identity);
      findings.push(finding(rule, file, item.line, identity));
    };

    if (isKubernetes) {
      const workloadSpecSuffixes: Record<string, string[][]> = {
        pod: [['spec']],
        deployment: [['spec', 'template', 'spec']],
        statefulset: [['spec', 'template', 'spec']],
        daemonset: [['spec', 'template', 'spec']],
        job: [['spec', 'template', 'spec']],
        cronjob: [['spec', 'jobtemplate', 'spec', 'template', 'spec']],
        replicaset: [['spec', 'template', 'spec']]
      };
      const workloadSpecs = values.flatMap((item) => {
        const lowerPath = item.path.map((part) => part.toLowerCase());
        const rootKind =
          lowerPath.length === 1 ||
          (lowerPath.at(-3) === 'items' &&
            /^\d+$/u.test(lowerPath.at(-2) ?? ''));
        if (
          !rootKind ||
          !pathEnds(item, 'kind') ||
          typeof item.value !== 'string'
        )
          return [];
        return (workloadSpecSuffixes[item.value.toLowerCase()] ?? []).map(
          (suffix) => ({
            path: [...item.path.slice(0, -1), ...suffix],
            documentIndex: item.documentIndex
          })
        );
      });
      type SpecTrieNode = {
        children: Map<string, SpecTrieNode>;
        spec?: { key: string; length: number };
      };
      const specTrie: SpecTrieNode = { children: new Map() };
      for (const { path: specPath, documentIndex } of workloadSpecs) {
        const key = `${documentIndex}\0${specPath
          .map((part) => part.toLowerCase())
          .join('\0')}`;
        let current: SpecTrieNode;
        const documentRoot = specTrie.children.get(String(documentIndex));
        if (documentRoot) current = documentRoot;
        else {
          current = { children: new Map() };
          specTrie.children.set(String(documentIndex), current);
        }
        for (const part of specPath) {
          const normalized = part.toLowerCase();
          let next: SpecTrieNode | undefined = current.children.get(normalized);
          if (!next) {
            next = { children: new Map() };
            current.children.set(normalized, next);
          }
          current = next;
        }
        current.spec = { key, length: specPath.length };
      }
      const specFor = (item: FlatYamlValue) => {
        let current = specTrie.children.get(String(item.documentIndex));
        let match = current?.spec;
        for (const part of item.path) {
          current = current?.children.get(part.toLowerCase());
          if (!current) break;
          if (current.spec) match = current.spec;
        }
        return match
          ? {
              key: match.key,
              relative: item.path
                .slice(match.length)
                .map((part) => part.toLowerCase())
            }
          : undefined;
      };
      const containerSafety = new Map<
        string,
        { sawValue: boolean; allTrue: boolean }
      >();
      const podSafety = new Map<
        string,
        { sawValue: boolean; allTrue: boolean }
      >();
      const containerImages: Array<{
        item: FlatYamlValue;
        containerKey: string;
        specKey: string;
      }> = [];
      for (const item of values) {
        const classified = specFor(item);
        if (!classified) continue;
        const { key: specKey, relative } = classified;
        const container =
          (relative[0] === 'containers' || relative[0] === 'initcontainers') &&
          /^\d+$/u.test(relative[1] ?? '');
        const containerKey = container
          ? `${specKey}\0${relative[0]}\0${relative[1]}`
          : '';
        if (
          item.value === true &&
          container &&
          relative.at(-2) === 'securitycontext' &&
          relative.at(-1) === 'privileged'
        )
          add('TLP-IAC-K8S-001', item);
        if (
          item.value === true &&
          container &&
          relative.at(-2) === 'securitycontext' &&
          relative.at(-1) === 'allowprivilegeescalation'
        )
          add('TLP-IAC-K8S-002', item);
        if (
          item.value === true &&
          relative.length === 1 &&
          relative[0] === 'hostnetwork'
        )
          add('TLP-IAC-K8S-003', item);
        if (
          pathEnds(item, 'path') &&
          relative.length === 4 &&
          relative[0] === 'volumes' &&
          /^\d+$/u.test(relative[1] ?? '') &&
          relative[2] === 'hostpath'
        )
          add('TLP-IAC-K8S-004', item);
        if (
          relative.length === 2 &&
          relative[0] === 'securitycontext' &&
          relative[1] === 'runasnonroot'
        ) {
          const state = podSafety.get(specKey) ?? {
            sawValue: false,
            allTrue: true
          };
          state.sawValue = true;
          state.allTrue &&= item.value === true;
          podSafety.set(specKey, state);
        }
        if (
          container &&
          relative.length === 4 &&
          relative[2] === 'securitycontext' &&
          relative[3] === 'runasnonroot'
        ) {
          const state = containerSafety.get(containerKey) ?? {
            sawValue: false,
            allTrue: true
          };
          state.sawValue = true;
          state.allTrue &&= item.value === true;
          containerSafety.set(containerKey, state);
        }
        if (
          pathEnds(item, 'image') &&
          relative.length === 3 &&
          (relative[0] === 'containers' || relative[0] === 'initcontainers') &&
          /^\d+$/u.test(relative[1] ?? '')
        ) {
          containerImages.push({ item, containerKey, specKey });
        }
      }
      for (const { item: image, containerKey, specKey } of containerImages) {
        const pod = podSafety.get(specKey);
        const container = containerSafety.get(containerKey);
        const podNonRoot = pod?.sawValue === true && pod.allTrue;
        const containerNonRoot =
          container?.sawValue === true && container.allTrue;
        if (!podNonRoot || (container?.sawValue && !container.allTrue)) {
          if (!containerNonRoot) add('TLP-IAC-K8S-005', image);
        }
      }
    }

    if (isWorkflow) {
      for (const item of values) {
        const key = item.path.at(-1)?.toLowerCase();
        if (
          item.path.some((part) => part.toLowerCase() === 'permissions') &&
          typeof item.value === 'string' &&
          item.value.toLowerCase() === 'write'
        ) {
          add('TLP-IAC-GHA-001', item);
        }
        if (key === 'permissions' && item.value === 'write-all') {
          add('TLP-IAC-GHA-001', item);
        }
        if (
          key === 'uses' &&
          typeof item.value === 'string' &&
          !item.value.startsWith('./') &&
          !(item.value.startsWith('docker://')
            ? /@sha256:[0-9a-f]{64}$/iu.test(item.value)
            : /@[0-9a-f]{40}$/iu.test(item.value))
        ) {
          add('TLP-IAC-GHA-002', item);
        }
        if (
          key === 'run' &&
          typeof item.value === 'string' &&
          /\$\{\{\s*(?:github\.event\.(?:(?:pull_request|issue|discussion)\.(?:title|body|head\.ref)|(?:issue_comment|pull_request_review|pull_request_review_comment|commit_comment)\.comment\.body|pull_request_review\.review\.body|commits\[\d+\]\.message|head_commit\.message|repository_dispatch\.client_payload\.[\w.]+|workflow_dispatch\.inputs\.[\w-]+)|github\.head_ref|inputs\.[\w-]+)\s*\}\}/iu.test(
            item.value
          )
        ) {
          add('TLP-IAC-GHA-003', item);
        }
      }
    }
  }
  return findings;
}

function countBraces(line: string): { opens: number; closes: number } {
  let quote = '';
  let escaped = false;
  let lineComment = false;
  let opens = 0;
  let closes = 0;
  for (let index = 0; index < line.length; index++) {
    const char = line[index] ?? '';
    const next = line[index + 1] ?? '';
    if (lineComment) break;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === quote) quote = '';
      continue;
    }
    if (char === '"') quote = char;
    else if (char === '#') lineComment = true;
    else if (char === '/' && next === '/') lineComment = true;
    else if (char === '{') opens++;
    else if (char === '}') closes++;
  }
  return { opens, closes };
}

function maskHclTrivia(source: string): string {
  let inBlockComment = false;
  let heredoc: { marker: string; indented: boolean } | undefined;
  const output: string[] = [];
  for (const line of source.split(/\r?\n/u)) {
    if (heredoc) {
      const closes = heredoc.indented
        ? line.trim() === heredoc.marker
        : line === heredoc.marker;
      output.push(line.replace(/[^\r\n]/gu, ' '));
      if (closes) heredoc = undefined;
      continue;
    }
    const masked = [...line];
    let quote = false;
    let escaped = false;
    for (let index = 0; index < line.length; index++) {
      const char = line[index] ?? '';
      const next = line[index + 1] ?? '';
      if (inBlockComment) {
        masked[index] = ' ';
        if (char === '*' && next === '/') {
          masked[index + 1] = ' ';
          index++;
          inBlockComment = false;
        }
        continue;
      }
      if (quote) {
        if (escaped) escaped = false;
        else if (char === '\\') escaped = true;
        else if (char === '"') quote = false;
        continue;
      }
      if (char === '"') {
        quote = true;
        continue;
      }
      if (char === '/' && next === '*') {
        masked[index] = masked[index + 1] = ' ';
        index++;
        inBlockComment = true;
        continue;
      }
      if (char === '#' || (char === '/' && next === '/')) {
        for (let rest = index; rest < line.length; rest++) masked[rest] = ' ';
        break;
      }
      if (char === '<' && next === '<') {
        const marker = line.slice(index).match(/^<<(-?)\s*([A-Za-z_][\w-]*)/u);
        if (marker?.[2]) {
          for (let rest = index; rest < line.length; rest++) masked[rest] = ' ';
          heredoc = { marker: marker[2], indented: marker[1] === '-' };
          break;
        }
      }
    }
    if (quote) throw new Error('unterminated Terraform string');
    output.push(masked.join(''));
  }
  if (inBlockComment) throw new Error('unterminated Terraform block comment');
  if (heredoc) throw new Error('unterminated Terraform heredoc');
  return output.join('\n');
}

function scanTerraform(file: string, source: string): Finding[] {
  const lines = maskHclTrivia(source).split('\n');
  let overallDepth = 0;
  for (const line of lines) {
    const braces = countBraces(line);
    overallDepth += braces.opens - braces.closes;
    if (overallDepth < 0) throw new Error('unexpected closing Terraform block');
  }
  if (overallDepth !== 0) throw new Error('unclosed Terraform block');
  const findings: Finding[] = [];
  for (let start = 0; start < lines.length; start++) {
    const declaration = lines[start]?.match(
      /^\s*resource\s+"([^"]+)"\s+"[^"]+"\s*\{/u
    );
    if (!declaration) continue;
    const resourceType = declaration[1] ?? '';
    let depth = 0;
    let end = start;
    for (; end < lines.length; end++) {
      const braces = countBraces(lines[end] ?? '');
      depth += braces.opens - braces.closes;
      if (depth === 0) break;
    }
    if (depth !== 0) throw new Error('unclosed Terraform resource block');
    const body = lines.slice(start, end + 1).join('\n');
    const addAt = (ruleId: string, pattern: RegExp) => {
      const rule = rules[ruleId];
      if (!rule) return;
      const index = lines
        .slice(start, end + 1)
        .findIndex((line) => pattern.test(line));
      if (index >= 0)
        findings.push(
          finding(
            rule,
            file,
            start + index + 1,
            `${ruleId}:${start + index + 1}`
          )
        );
    };
    if (
      ['aws_s3_bucket', 'aws_s3_bucket_acl'].includes(resourceType) &&
      /\bacl\s*=\s*"public-read(?:-write)?"/i.test(body)
    ) {
      addAt('TLP-IAC-TF-001', /\bacl\s*=\s*"public-read(?:-write)?"/i);
    }
    if (resourceType === 'aws_s3_bucket_public_access_block') {
      addAt(
        'TLP-IAC-TF-001',
        /\b(?:block_public_acls|block_public_policy|restrict_public_buckets)\s*=\s*false\b/iu
      );
    }
    if (
      resourceType === 'aws_s3_bucket_policy' &&
      /(?:Principal\s*=\s*"\*"|"Principal"\s*:\s*"\*")/u.test(body) &&
      /(?:Effect\s*=\s*"Allow"|"Effect"\s*:\s*"Allow")/iu.test(body)
    ) {
      addAt(
        'TLP-IAC-TF-005',
        /(?:Principal\s*=\s*"\*"|"Principal"\s*:\s*"\*")/u
      );
    }
    if (resourceType === 'aws_security_group') {
      const ingressBlocks = [...body.matchAll(/ingress\s*\{[^}]*\}/giu)].map(
        (match) => ({ block: match[0] ?? '', offset: match.index ?? 0 })
      );
      const publicIngress = (block: string) =>
        /(?:cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"|ipv6_cidr_blocks\s*=\s*\[[^\]]*"::\/0")/iu.test(
          block
        );
      const administrationIngress = (block: string) => {
        const from = Number(block.match(/from_port\s*=\s*(-?\d+)/iu)?.[1]);
        const to = Number(block.match(/to_port\s*=\s*(-?\d+)/iu)?.[1]);
        if (from === -1 || to === -1) return true;
        return [22, 3389].some(
          (port) =>
            Number.isFinite(from) &&
            Number.isFinite(to) &&
            from <= port &&
            port <= to
        );
      };
      const addAtOffset = (ruleId: string, offset: number) => {
        const line = start + body.slice(0, offset).split('\n').length;
        const rule = rules[ruleId];
        if (rule) findings.push(finding(rule, file, line, `${ruleId}:${line}`));
      };
      for (const ingress of ingressBlocks) {
        if (!publicIngress(ingress.block)) continue;
        addAtOffset(
          administrationIngress(ingress.block)
            ? 'TLP-IAC-TF-002'
            : 'TLP-IAC-TF-004',
          ingress.offset
        );
      }
    }
    if (
      resourceType === 'aws_security_group_rule' ||
      resourceType === 'aws_vpc_security_group_ingress_rule'
    ) {
      const ingress =
        resourceType === 'aws_vpc_security_group_ingress_rule' ||
        /^\s*type\s*=\s*"ingress"\s*$/imu.test(body);
      const publicSource =
        /(?:cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"|ipv6_cidr_blocks\s*=\s*\[[^\]]*"::\/0"|cidr_ipv4\s*=\s*"0\.0\.0\.0\/0"|cidr_ipv6\s*=\s*"::\/0")/iu.test(
          body
        );
      if (ingress && publicSource) {
        const from = Number(body.match(/from_port\s*=\s*(-?\d+)/iu)?.[1]);
        const to = Number(body.match(/to_port\s*=\s*(-?\d+)/iu)?.[1]);
        const protocol = body.match(/(?:ip_)?protocol\s*=\s*"([^"]+)"/iu)?.[1];
        const administrationPorts =
          protocol === '-1' ||
          from === -1 ||
          to === -1 ||
          [22, 3389].some(
            (port) =>
              Number.isFinite(from) &&
              Number.isFinite(to) &&
              from <= port &&
              port <= to
          );
        addAt(
          administrationPorts ? 'TLP-IAC-TF-002' : 'TLP-IAC-TF-004',
          /(?:cidr_blocks\s*=|ipv6_cidr_blocks\s*=|cidr_ipv4\s*=|cidr_ipv6\s*=)/iu
        );
      }
    }
    if (
      resourceType === 'google_storage_bucket_iam_binding' ||
      resourceType === 'google_storage_bucket_iam_member'
    ) {
      const publicMember =
        /\bmember\s*=\s*"allUsers"/u.test(body) ||
        /\bmembers\s*=\s*\[[^\]]*"all(?:Authenticated)?Users"/u.test(body);
      if (publicMember)
        addAt(
          'TLP-IAC-TF-006',
          /\bmembers?\s*=\s*(?:"allUsers"|\[[^\]]*"all(?:Authenticated)?Users")/u
        );
    }
    if (
      resourceType === 'azurerm_storage_account' &&
      /^\s*allow_nested_items_to_be_public\s*=\s*true\s*$/imu.test(body)
    ) {
      addAt(
        'TLP-IAC-TF-007',
        /^\s*allow_nested_items_to_be_public\s*=\s*true\s*$/imu
      );
    }
    if (resourceType === 'google_compute_firewall') {
      const publicSource =
        !/^\s*direction\s*=\s*"EGRESS"\s*$/imu.test(body) &&
        /\bsource_ranges\s*=\s*\[[^\]]*"(?:0\.0\.0\.0\/0|::\/0)"/iu.test(body);
      if (publicSource) {
        const allowBlocks = [...body.matchAll(/\ballow\s*\{[^}]*\}/giu)];
        for (const block of allowBlocks) {
          const value = block[0] ?? '';
          const ports = value.match(/\bports\s*=\s*\[([^\]]*)\]/iu)?.[1];
          const protocol = value.match(/\bprotocol\s*=\s*"([^"]+)"/iu)?.[1];
          const numericPorts = [
            ...(ports ?? '').matchAll(/"(\d+)(?:-(\d+))?"/gu)
          ];
          const administrationPorts =
            protocol === 'all' ||
            numericPorts.some((match) => {
              const from = Number(match[1]);
              const to = Number(match[2] ?? match[1]);
              return [22, 3389].some((port) => from <= port && port <= to);
            });
          if (ports === undefined || numericPorts.length === 0) {
            // Omitting ports exposes every port for the declared protocol.
            if (protocol !== 'tcp' && protocol !== 'udp' && protocol !== 'all')
              continue;
          }
          const offset = block.index ?? 0;
          const ruleId = administrationPorts
            ? 'TLP-IAC-TF-002'
            : 'TLP-IAC-TF-004';
          const line = start + body.slice(0, offset).split('\n').length;
          const rule = rules[ruleId];
          if (rule)
            findings.push(finding(rule, file, line, `${ruleId}:${line}`));
        }
      }
    }
    if (resourceType === 'azurerm_network_security_rule') {
      const inboundAllow =
        /^\s*direction\s*=\s*"Inbound"\s*$/imu.test(body) &&
        /^\s*access\s*=\s*"Allow"\s*$/imu.test(body);
      const publicSource =
        /\bsource_address_prefix(?:es)?\s*=\s*(?:"(?:\*|Internet|0\.0\.0\.0\/0|::\/0)"|\[[^\]]*"(?:\*|Internet|0\.0\.0\.0\/0|::\/0)")/iu.test(
          body
        );
      if (inboundAllow && publicSource) {
        const ports = [
          ...body.matchAll(/destination_port_ranges?\s*=\s*\[([^\]]*)\]/giu),
          ...body.matchAll(/destination_port_range\s*=\s*"([^"]+)"/giu)
        ]
          .map((match) => match[1] ?? '')
          .join(',');
        const numericPorts = [...ports.matchAll(/(?:"|\b)(\d+)(?:-(\d+))?/gu)];
        const administrationPorts =
          ports.includes('*') ||
          numericPorts.length === 0 ||
          numericPorts.some((match) => {
            const from = Number(match[1]);
            const to = Number(match[2] ?? match[1]);
            return [22, 3389].some((port) => from <= port && port <= to);
          });
        addAt(
          administrationPorts ? 'TLP-IAC-TF-002' : 'TLP-IAC-TF-004',
          /\bsource_address_prefix(?:es)?\s*=/iu
        );
      }
    }
    if (
      ['aws_iam_policy', 'aws_iam_role_policy'].includes(resourceType) &&
      /(?:actions?|Action)\s*=\s*(?:\[\s*"\*"\s*\]|"\*")/u.test(body) &&
      /(?:resources?|Resource)\s*=\s*(?:\[\s*"\*"\s*\]|"\*")/u.test(body)
    ) {
      addAt(
        'TLP-IAC-TF-003',
        /(?:actions?|Action)\s*=\s*(?:\[\s*"\*"\s*\]|"\*")/u
      );
    }
    start = end;
  }
  return findings;
}

function terraformModuleSourceIssues(
  file: string,
  source: string,
  projectTerraformDirectories: ReadonlySet<string>
): string[] {
  const lines = maskHclTrivia(source).split('\n');
  const issues: string[] = [];
  for (let start = 0; start < lines.length; start++) {
    if (!/^\s*module\s+"[^"\n]+"\s*\{/u.test(lines[start] ?? '')) continue;
    let depth = 0;
    let end = start;
    for (; end < lines.length; end++) {
      const braces = countBraces(lines[end] ?? '');
      depth += braces.opens - braces.closes;
      if (depth === 0) break;
    }
    if (depth !== 0) throw new Error('unclosed Terraform module block');
    const assignments = lines
      .slice(start + 1, end)
      .map((line) => /^\s*source\s*=\s*(.*?)\s*$/u.exec(line))
      .filter((match) => match !== null);
    if (assignments.length !== 1) {
      issues.push('terraform-module-source-unresolved');
      start = end;
      continue;
    }
    const rawSource = assignments[0]?.[1]?.trim() ?? '';
    if (!rawSource.startsWith('"')) {
      issues.push('terraform-module-source-dynamic');
      start = end;
      continue;
    }
    if (!/^"(?:\\.|[^"\\])*"$/u.test(rawSource)) {
      issues.push('terraform-module-source-unresolved');
      start = end;
      continue;
    }
    let moduleSource: string;
    try {
      moduleSource = JSON.parse(rawSource) as string;
    } catch {
      issues.push('terraform-module-source-unresolved');
      start = end;
      continue;
    }
    if (moduleSource.includes('${') || moduleSource.includes('%{')) {
      issues.push('terraform-module-source-dynamic');
      start = end;
      continue;
    }
    if (!moduleSource.startsWith('./') && !moduleSource.startsWith('../')) {
      issues.push('terraform-remote-module-unresolved');
      start = end;
      continue;
    }
    const target = path.posix.normalize(
      path.posix.join(path.posix.dirname(file), moduleSource)
    );
    if (
      path.posix.isAbsolute(target) ||
      target === '..' ||
      target.startsWith('../')
    ) {
      issues.push('terraform-local-module-outside-project');
      start = end;
      continue;
    }
    if (!projectTerraformDirectories.has(target))
      issues.push('terraform-local-module-unavailable');
    start = end;
  }
  return issues;
}

function candidate(
  file: string,
  content: string
): 'terraform' | 'yaml' | undefined {
  const normalized = file.replaceAll('\\', '/').toLowerCase();
  if (normalized.endsWith('.tf')) return 'terraform';
  if (!/\.(?:ya?ml)$/i.test(normalized)) return undefined;
  if (
    /(^|\/)\.github\/workflows\//.test(normalized) ||
    /(^|\/)(k8s|kubernetes|manifests)(\/|$)/i.test(normalized) ||
    /^\s*apiVersion\s*:/m.test(content)
  )
    return 'yaml';
  return undefined;
}

/** Bounded static checks for Terraform, Kubernetes manifests and GitHub Actions. */
export class InfrastructureAnalyzer implements Analyzer {
  readonly id = 'infrastructure-security';
  readonly version = '1.0.0';

  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const scanner =
      (context.options?.scannerContext as ScannerContext | undefined) ??
      (await createScannerContext(context.root));
    const reader = new TextFileReader(undefined, { root: scanner.root });
    const contentProvider = context.options?.contentProvider as
      ((file: ProjectFile) => Promise<TextFileReadResult>) | undefined;
    const projectTerraformDirectories = new Set<string>();
    for (const file of scanner.files) {
      if (!file.relativePath.toLowerCase().endsWith('.tf')) continue;
      let directory = path.posix.dirname(
        file.relativePath.replaceAll('\\', '/')
      );
      projectTerraformDirectories.add(directory);
      while (directory !== '.') {
        directory = path.posix.dirname(directory);
        projectTerraformDirectories.add(directory);
      }
    }
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let eligible = 0;
    let scanned = 0;
    let skipped = 0;
    let failed = 0;
    let bytesAnalyzed = 0;
    let cancelled = false;

    for (const file of scanner.files) {
      if (context.signal?.aborted) {
        cancelled = true;
        break;
      }
      const normalizedPath = file.relativePath.replaceAll('\\', '/');
      const possibleInfrastructureInput =
        /\.tf$/iu.test(normalizedPath) || /\.ya?ml$/iu.test(normalizedPath);
      if (!possibleInfrastructureInput) continue;
      const read = contentProvider
        ? await contentProvider(file)
        : await reader.read(file.absolutePath, context.signal, file.snapshot);
      if (read.status !== 'ok') {
        if (read.status === 'cancelled') cancelled = true;
        const kind =
          candidate(file.relativePath, '') ??
          (file.relativePath.toLowerCase().endsWith('.tf')
            ? 'terraform'
            : /\.ya?ml$/iu.test(file.relativePath)
              ? 'yaml'
              : undefined);
        if (kind) {
          eligible++;
          if (read.status === 'failed') failed++;
          else skipped++;
          warnings.push(
            `${file.relativePath}: analysis incomplete (${read.status})`
          );
        }
        continue;
      }
      bytesAnalyzed += read.bytes;
      const kind = candidate(file.relativePath, read.content);
      if (!kind) continue;
      eligible++;
      try {
        const current =
          kind === 'terraform'
            ? scanTerraform(file.relativePath, read.content)
            : scanYaml(file.relativePath, read.content);
        findings.push(...bindSourceProvenance(current, file, read));
        if (kind === 'terraform') {
          for (const issue of terraformModuleSourceIssues(
            normalizedPath,
            read.content,
            projectTerraformDirectories
          )) {
            eligible++;
            skipped++;
            warnings.push(`${file.relativePath}: ${issue}`);
          }
        }
        scanned++;
      } catch (error) {
        failed++;
        warnings.push(
          `${file.relativePath}: analysis failed (${error instanceof Error ? error.message : 'invalid input'})`
        );
      }
    }
    return {
      analyzer: this.id,
      durationMs: Math.round(performance.now() - startedAt),
      findings: findings.sort((left, right) => {
        const fileOrder = (left.location?.file ?? '').localeCompare(
          right.location?.file ?? ''
        );
        if (fileOrder !== 0) return fileOrder;
        const lineOrder =
          (left.location?.line ?? 0) - (right.location?.line ?? 0);
        return lineOrder || left.ruleId.localeCompare(right.ruleId);
      }),
      coverage: coverageOf({ eligible, scanned, skipped, failed, cancelled }),
      warnings: warnings.length ? warnings : undefined,
      metadata: {
        eligible,
        scanned,
        findings: findings.length,
        bytesAnalyzed: bytesAnalyzed || reader.usage.bytesRead
      }
    };
  }
}
