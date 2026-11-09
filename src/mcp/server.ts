import { TOOLIP_VERSION } from '../config/version.js';
import { ToolipError } from '../errors/toolip-error.js';
import path from 'node:path';
import { realpath } from 'node:fs/promises';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { runSecurityDoctor } from '../core/security-doctor.js';
import { generateSbom } from '../core/sbom/generate.js';
import { securityDiff } from '../core/diff/security-diff.js';
import {
  createProjectSnapshot,
  dependencyFileSourceFromSnapshot
} from '../application/project-snapshot.js';
import { buildSecurityScorecard } from '../application/security-scorecard.js';
import {
  evaluatePolicyAsCode,
  parsePolicyAsCode,
  loadTrustedOrganizationPolicy,
  mergePolicyLayers
} from '../core/policy-as-code.js';
import {
  sanitizeOutput,
  serializeSanitizedOutputBounded
} from '../core/safe-output.js';
import { createWorkspaceBoundary } from './workspace-boundary.js';
import type { PolicyDecision } from '../core/policy-as-code.js';

export type McpServerOptions = {
  allowedRoots?: readonly string[];
  capabilities?: Partial<Record<McpCapability, boolean>>;
  maxResponseBytes?: number;
  maxConcurrentTools?: number;
  maxToolCalls?: number;
  toolTimeoutMs?: number;
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  /** Out-of-band organization policy trust configuration. Never read from the repository. */
  organizationPolicy?: {
    filePath: string;
    publicKeyPath: string;
    trustedKeyId: string;
    trustedIssuer: string;
  };
  requireOrganizationPolicy?: boolean;
};

export const mcpCapabilityNames = [
  'read-code',
  'read-git',
  'scan',
  'external-network',
  'write-reports',
  'create-pr',
  'vault-access'
] as const;
export type McpCapability = (typeof mcpCapabilityNames)[number];

/** Closed, deeply immutable authorization matrix: new tools need an entry. */
export const mcpToolCapabilities = Object.freeze({
  toolip_doctor: Object.freeze(['read-code', 'scan']),
  toolip_policy_check: Object.freeze(['read-code', 'read-git', 'scan']),
  toolip_sbom: Object.freeze(['read-code', 'scan']),
  toolip_diff: Object.freeze(['read-code', 'read-git', 'scan'])
} as const satisfies Record<string, readonly McpCapability[]>);

const defaultCapabilities: Readonly<Record<McpCapability, boolean>> = {
  'read-code': true,
  'read-git': true,
  scan: true,
  'external-network': false,
  'write-reports': false,
  'create-pr': false,
  'vault-access': false
};

export class McpBudgetError extends Error {
  constructor(
    readonly code:
      | 'MCP_CALL_LIMIT'
      | 'MCP_CONCURRENCY_LIMIT'
      | 'MCP_TIMEOUT'
      | 'MCP_CANCELLED',
    message: string
  ) {
    super(message);
    this.name = 'McpBudgetError';
  }
}

/** Process-local request, concurrency, timeout and cancellation budget. */
export class McpResourceBudget {
  private active = 0;
  private calls = 0;

  constructor(
    private readonly limits: {
      maxConcurrentTools: number;
      maxToolCalls: number;
      toolTimeoutMs: number;
    }
  ) {
    if (
      !Number.isSafeInteger(limits.maxConcurrentTools) ||
      limits.maxConcurrentTools < 1 ||
      limits.maxConcurrentTools > 32 ||
      !Number.isSafeInteger(limits.maxToolCalls) ||
      limits.maxToolCalls < 1 ||
      limits.maxToolCalls > 100_000 ||
      !Number.isSafeInteger(limits.toolTimeoutMs) ||
      limits.toolTimeoutMs < 1 ||
      limits.toolTimeoutMs > 900_000
    )
      throw new RangeError(
        'MCP concurrency, call and timeout budgets are outside the supported limits.'
      );
  }

  async run<T>(
    operation: (signal: AbortSignal) => Promise<T>,
    outerSignal?: AbortSignal
  ): Promise<T> {
    this.calls++;
    if (this.calls > this.limits.maxToolCalls) {
      throw new McpBudgetError(
        'MCP_CALL_LIMIT',
        'MCP tool-call budget has been exhausted.'
      );
    }
    if (this.active >= this.limits.maxConcurrentTools) {
      throw new McpBudgetError(
        'MCP_CONCURRENCY_LIMIT',
        'MCP concurrent-tool budget is currently full.'
      );
    }
    if (outerSignal?.aborted) {
      throw new McpBudgetError('MCP_CANCELLED', 'MCP request was cancelled.');
    }

    this.active++;
    const controller = new AbortController();
    let rejectStopped: ((error: McpBudgetError) => void) | undefined;
    const stopped = new Promise<never>((_resolve, reject) => {
      rejectStopped = reject;
    });
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
      rejectStopped?.(
        new McpBudgetError('MCP_TIMEOUT', 'MCP tool exceeded its time budget.')
      );
    }, this.limits.toolTimeoutMs);
    const abort = (): void => {
      controller.abort(outerSignal?.reason);
      rejectStopped?.(
        new McpBudgetError('MCP_CANCELLED', 'MCP request was cancelled.')
      );
    };
    outerSignal?.addEventListener('abort', abort, { once: true });
    if (outerSignal?.aborted) abort();

    let released = false;
    const release = (): void => {
      if (released) return;
      released = true;
      this.active--;
    };
    const task = Promise.resolve()
      .then(() => {
        if (controller.signal.aborted) {
          throw new McpBudgetError(
            timedOut ? 'MCP_TIMEOUT' : 'MCP_CANCELLED',
            timedOut
              ? 'MCP tool exceeded its time budget.'
              : 'MCP request was cancelled.'
          );
        }
        return operation(controller.signal);
      })
      .then((value) => {
        if (controller.signal.aborted) {
          throw new McpBudgetError(
            timedOut ? 'MCP_TIMEOUT' : 'MCP_CANCELLED',
            timedOut
              ? 'MCP tool exceeded its time budget.'
              : 'MCP request was cancelled.'
          );
        }
        return value;
      });
    void task.then(release, release);
    try {
      return await Promise.race([task, stopped]);
    } finally {
      clearTimeout(timeout);
      outerSignal?.removeEventListener('abort', abort);
    }
  }
}

function requestIdValue(value: unknown): string | number | undefined {
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (typeof value === 'string' && value.length <= 128) return value;
  return undefined;
}

function responseLimitPayload() {
  return {
    error: {
      code: 'MCP_RESPONSE_LIMIT',
      message: 'Tool response exceeds the configured byte or structure limit.'
    },
    decision: 'incomplete',
    incomplete: true,
    outputTruncated: true
  };
}

function mcpFailure(
  code: string,
  message: string,
  maxResponseBytes: number,
  requestId?: string | number,
  decision?: PolicyDecision
) {
  const id = requestIdValue(requestId);
  const metadata =
    id === undefined ? {} : { _meta: { 'toolip/requestId': id } };
  const text = serializeMcpOutput({
    error: {
      code: code.slice(0, 128),
      message: message.slice(0, 512),
      ...(id === undefined ? {} : { requestId: id }),
      ...(decision ? { decision } : {})
    }
  });
  return {
    ...metadata,
    ...(decision ? { decision } : {}),
    isError: true,
    content: [
      {
        type: 'text' as const,
        text:
          Buffer.byteLength(text) <= maxResponseBytes
            ? text
            : JSON.stringify(responseLimitPayload())
      }
    ]
  };
}

export function resolveMcpCapabilities(
  requested: McpServerOptions['capabilities'] = {}
): Readonly<Record<McpCapability, boolean>> {
  if (!requested || typeof requested !== 'object' || Array.isArray(requested))
    throw new TypeError('MCP capabilities must be a plain object.');
  const prototype = Object.getPrototypeOf(requested);
  if (prototype !== Object.prototype && prototype !== null)
    throw new TypeError('MCP capabilities must be a plain object.');
  const allowed = new Set<string>(mcpCapabilityNames);
  const overrides: Partial<Record<McpCapability, boolean>> = {};
  for (const name of Reflect.ownKeys(requested)) {
    if (typeof name !== 'string')
      throw new TypeError('MCP capability names must be strings.');
    if (!allowed.has(name))
      throw new TypeError(`Unknown MCP capability: ${name}.`);
    const descriptor = Object.getOwnPropertyDescriptor(requested, name);
    if (!descriptor?.enumerable || !('value' in descriptor))
      throw new TypeError(`MCP capability ${name} must be a data property.`);
    const value = descriptor.value;
    if (typeof value !== 'boolean')
      throw new TypeError(`MCP capability ${name} must be boolean.`);
    overrides[name as McpCapability] = value;
  }
  return Object.freeze({ ...defaultCapabilities, ...overrides });
}

function capabilityDenied(
  capabilities: Readonly<Record<McpCapability, boolean>>,
  required: readonly McpCapability[]
): boolean {
  return required.some((capability) => capabilities[capability] !== true);
}

function isWithinRoot(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === '' ||
    (!path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`))
  );
}

export function isMcpToolAuthorized(
  toolName: string,
  capabilities: Readonly<Record<McpCapability, boolean>>
): boolean {
  if (!Object.hasOwn(mcpToolCapabilities, toolName)) return false;
  return !capabilityDenied(
    capabilities,
    mcpToolCapabilities[toolName as keyof typeof mcpToolCapabilities]
  );
}

export async function boundedMcpTextResponse(
  value: unknown,
  maxResponseBytes: number,
  requestId?: unknown,
  signal?: AbortSignal
): Promise<{
  _meta?: { 'toolip/requestId': string | number };
  isError?: boolean;
  content: Array<{ type: 'text'; text: string }>;
}> {
  if (
    !Number.isSafeInteger(maxResponseBytes) ||
    maxResponseBytes < 1_024 ||
    maxResponseBytes > 16_777_216
  )
    throw new RangeError(
      'MCP response budget must be between 1 KiB and 16 MiB.'
    );
  const id = requestIdValue(requestId);
  const metadata =
    id === undefined ? {} : { _meta: { 'toolip/requestId': id } };
  try {
    const text = await serializeSanitizedOutputBounded(
      value,
      maxResponseBytes,
      signal
    );
    return { ...metadata, content: [{ type: 'text' as const, text }] };
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error;
    if (!(error instanceof RangeError)) throw error;
  }
  return {
    ...metadata,
    isError: true,
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(responseLimitPayload())
      }
    ]
  };
}

/** Serializes MCP tool output after applying the shared secret redactor. */
export function serializeMcpOutput(value: unknown): string {
  return JSON.stringify(sanitizeOutput(value), null, 2);
}

/** Starts local MCP tools with approved workspace boundaries and safe output. */
export async function startMcpServer(
  options: McpServerOptions = {}
): Promise<void> {
  const capabilities = resolveMcpCapabilities(options.capabilities);
  const maxResponseBytes = options.maxResponseBytes ?? 1_048_576;
  const maxConcurrentTools = options.maxConcurrentTools ?? 2;
  const maxToolCalls = options.maxToolCalls ?? 1_000;
  const toolTimeoutMs = options.toolTimeoutMs ?? 120_000;
  const maxFiles = options.maxFiles ?? 20_000;
  const maxFileBytes = options.maxFileBytes ?? 2 * 1024 * 1024;
  const maxTotalBytes = options.maxTotalBytes ?? 64 * 1024 * 1024;
  if (
    !Number.isSafeInteger(maxResponseBytes) ||
    maxResponseBytes < 1_024 ||
    maxResponseBytes > 16_777_216
  ) {
    throw new RangeError(
      'MCP response budget must be between 1 KiB and 16 MiB.'
    );
  }
  if (
    !Number.isSafeInteger(maxFiles) ||
    maxFiles < 1 ||
    maxFiles > 50_000 ||
    !Number.isSafeInteger(maxFileBytes) ||
    maxFileBytes < 1 ||
    maxFileBytes > 16 * 1024 * 1024 ||
    !Number.isSafeInteger(maxTotalBytes) ||
    maxTotalBytes < maxFileBytes ||
    maxTotalBytes > 512 * 1024 * 1024
  ) {
    throw new RangeError('MCP scan budgets are outside the supported limits.');
  }
  const toolBudget = new McpResourceBudget({
    maxConcurrentTools,
    maxToolCalls,
    toolTimeoutMs
  });
  if (options.requireOrganizationPolicy && !options.organizationPolicy)
    throw new Error(
      'MCP requires an independently configured organization policy.'
    );
  const boundary = await createWorkspaceBoundary(
    options.allowedRoots ?? [process.cwd()]
  );
  const organizationPolicy = options.organizationPolicy;
  if (organizationPolicy) {
    const trustedPaths = await Promise.all([
      realpath(path.resolve(organizationPolicy.filePath)),
      realpath(path.resolve(organizationPolicy.publicKeyPath))
    ]);
    if (
      trustedPaths.some((candidate) =>
        boundary.allowedRoots.some((root) => isWithinRoot(root, candidate))
      )
    )
      throw new Error(
        'MCP organization policy and trust key must resolve outside approved workspaces.'
      );
  }
  const defaultRoot = boundary.allowedRoots[0];

  if (!defaultRoot) {
    throw new Error('MCP workspace boundary has no approved root.');
  }

  const server = new McpServer({
    name: 'toolip',
    version: TOOLIP_VERSION
  });

  server.registerTool(
    'toolip_doctor',
    {
      title: 'Toolip Security Doctor',
      description:
        'Run local Toolip security checks inside an approved workspace.',
      inputSchema: {
        root: z.string().max(4_096).default(defaultRoot)
      }
    },
    async ({ root }, extra) => {
      if (!isMcpToolAuthorized('toolip_doctor', capabilities)) {
        return mcpFailure(
          'MCP_CAPABILITY_DENIED',
          'Tool requires read-code and scan capabilities.',
          maxResponseBytes,
          requestIdValue(extra.requestId)
        );
      }
      try {
        return await toolBudget.run(async (signal) => {
          const approvedRoot = await boundary.resolve(root);
          const snapshot = await createProjectSnapshot(approvedRoot, {
            signal,
            maxFiles,
            maxFileBytes,
            maxTotalBytes
          });
          const report = await runSecurityDoctor(approvedRoot, {
            signal,
            snapshot,
            budget: { maxFiles, maxFileBytes, maxTotalBytes }
          });
          return await boundedMcpTextResponse(
            report,
            maxResponseBytes,
            extra.requestId,
            signal
          );
        }, extra.signal);
      } catch (error) {
        if (error instanceof McpBudgetError)
          return mcpFailure(
            error.code,
            error.message,
            maxResponseBytes,
            requestIdValue(extra.requestId)
          );
        return mcpFailure(
          'MCP_SCAN_FAILED',
          'Security analysis failed; no clean result was issued.',
          maxResponseBytes,
          requestIdValue(extra.requestId)
        );
      }
    }
  );

  server.registerTool(
    'toolip_policy_check',
    {
      title: 'Toolip Policy Check',
      description:
        'Evaluate a versioned repository policy against a bounded immutable scan. Repository policy cannot authorize its own suppressions.',
      inputSchema: {
        root: z.string().max(4_096).default(defaultRoot),
        policyFile: z.string().min(1).max(4_096).default('.toolip/policy.yaml'),
        offline: z.boolean().default(true)
      }
    },
    async ({ root, policyFile, offline }, extra) => {
      if (!isMcpToolAuthorized('toolip_policy_check', capabilities)) {
        return mcpFailure(
          'MCP_CAPABILITY_DENIED',
          'Tool requires read-code, read-git and scan capabilities.',
          maxResponseBytes,
          requestIdValue(extra.requestId),
          'error'
        );
      }
      if (
        path.isAbsolute(policyFile) ||
        policyFile.split(/[\\/]+/u).includes('..')
      ) {
        return mcpFailure(
          'MCP_POLICY_PATH_DENIED',
          'Policy file must be a relative path inside the approved workspace.',
          maxResponseBytes,
          requestIdValue(extra.requestId),
          'misconfigured'
        );
      }
      if (!offline && capabilities['external-network'] !== true) {
        return mcpFailure(
          'MCP_CAPABILITY_DENIED',
          'Networked policy checks require the external-network capability.',
          maxResponseBytes,
          requestIdValue(extra.requestId),
          'misconfigured'
        );
      }
      let failureDecision: PolicyDecision = 'error';
      try {
        return await toolBudget.run(async (signal) => {
          const approvedRoot = await boundary.resolve(root);
          const candidate = path.resolve(approvedRoot, policyFile);
          const policyPath = await realpath(candidate);
          const relative = path.relative(approvedRoot, policyPath);
          if (
            path.isAbsolute(relative) ||
            relative === '..' ||
            relative.startsWith(`..${path.sep}`)
          ) {
            return mcpFailure(
              'MCP_POLICY_PATH_DENIED',
              'Policy file must stay inside the approved workspace.',
              maxResponseBytes,
              requestIdValue(extra.requestId),
              'misconfigured'
            );
          }
          failureDecision = 'incomplete';
          const snapshot = await createProjectSnapshot(approvedRoot, {
            signal,
            maxFiles,
            maxFileBytes,
            maxTotalBytes
          });
          const snapshotPolicyPath = path
            .relative(approvedRoot, policyPath)
            .split(path.sep)
            .join('/');
          const capturedPolicyFile = snapshot.files.find(
            (file) => file.path === snapshotPolicyPath
          );
          if (capturedPolicyFile?.content === undefined)
            throw new Error(
              'repository policy was not captured as bounded text in the project snapshot'
            );
          failureDecision = 'misconfigured';
          const loaded = parsePolicyAsCode(capturedPolicyFile.content);
          const organization = organizationPolicy
            ? await loadTrustedOrganizationPolicy(organizationPolicy)
            : undefined;
          const effective = mergePolicyLayers(
            loaded.policy,
            organization
              ? {
                  policy: organization.policy,
                  trust: {
                    trusted: true,
                    source: 'signed',
                    identity: organization.identity
                  }
                }
              : undefined
          );
          failureDecision = 'error';
          const scan = await buildSecurityScorecard(
            approvedRoot,
            {},
            {
              projectSnapshot: snapshot,
              budget: { signal },
              offline
            }
          );
          const evaluation = evaluatePolicyAsCode({
            policy: effective.policy,
            trust: effective.trust,
            findings: scan.findings,
            analysisState: scan.analysis.state,
            coverage: scan.coverage
          });
          return await boundedMcpTextResponse(
            {
              decision: evaluation.decision,
              decisionSha256: evaluation.policySha256,
              policy: {
                version: loaded.policy.version,
                sha256: loaded.sha256,
                organizationSha256: organization?.sha256,
                organizationIdentity: organization?.identity,
                trusted: effective.trust.trusted,
                ruleSets: effective.policy.ruleSets ?? ['all']
              },
              analysis: {
                state: scan.analysis.state,
                coverage: scan.coverage
              },
              reasons: evaluation.reasons,
              findings: evaluation.findings.map((finding) => ({
                id: finding.id,
                ruleId: finding.ruleId,
                title: finding.title,
                severity: finding.severity,
                message: finding.message,
                location: finding.location
              }))
            },
            maxResponseBytes,
            extra.requestId,
            signal
          );
        }, extra.signal);
      } catch (error) {
        if (error instanceof McpBudgetError)
          return mcpFailure(
            error.code,
            error.message,
            maxResponseBytes,
            requestIdValue(extra.requestId),
            'incomplete'
          );
        return mcpFailure(
          'MCP_POLICY_FAILED',
          'Policy validation or scan failed; no pass decision was issued.',
          maxResponseBytes,
          requestIdValue(extra.requestId),
          failureDecision
        );
      }
    }
  );

  server.registerTool(
    'toolip_sbom',
    {
      title: 'Generate SBOM',
      description:
        'Generate a local CycloneDX or SPDX SBOM inside an approved workspace.',
      inputSchema: {
        root: z.string().max(4_096).default(defaultRoot),
        format: z.enum(['cyclonedx', 'spdx']).default('cyclonedx')
      }
    },
    async ({ root, format }, extra) => {
      if (!isMcpToolAuthorized('toolip_sbom', capabilities)) {
        return mcpFailure(
          'MCP_CAPABILITY_DENIED',
          'Tool requires read-code and scan capabilities.',
          maxResponseBytes,
          requestIdValue(extra.requestId)
        );
      }
      try {
        return await toolBudget.run(async (signal) => {
          const approvedRoot = await boundary.resolve(root);
          const snapshot = await createProjectSnapshot(approvedRoot, {
            signal,
            maxFiles,
            maxFileBytes,
            maxTotalBytes
          });
          const report = await generateSbom(approvedRoot, format, {
            fileSource: dependencyFileSourceFromSnapshot(snapshot),
            signal
          });
          return await boundedMcpTextResponse(
            report,
            maxResponseBytes,
            extra.requestId,
            signal
          );
        }, extra.signal);
      } catch (error) {
        if (error instanceof McpBudgetError)
          return mcpFailure(
            error.code,
            error.message,
            maxResponseBytes,
            requestIdValue(extra.requestId)
          );
        return mcpFailure(
          'MCP_SBOM_FAILED',
          'SBOM generation failed; dependency coverage was not reported as complete.',
          maxResponseBytes,
          requestIdValue(extra.requestId)
        );
      }
    }
  );

  server.registerTool(
    'toolip_diff',
    {
      title: 'Security Diff',
      description:
        'Summarize security-relevant Git changes inside an approved workspace.',
      inputSchema: {
        root: z.string().max(4_096).default(defaultRoot),
        base: z.string().min(1).max(200),
        head: z.string().min(1).max(200).default('HEAD')
      }
    },
    async ({ root, base, head }, extra) => {
      if (!isMcpToolAuthorized('toolip_diff', capabilities)) {
        return mcpFailure(
          'MCP_CAPABILITY_DENIED',
          'Tool requires read-code, read-git and scan capabilities.',
          maxResponseBytes,
          requestIdValue(extra.requestId)
        );
      }
      try {
        return await toolBudget.run(async (signal) => {
          const approvedRoot = await boundary.resolve(root);
          const result = await securityDiff(approvedRoot, base, head, signal);
          return await boundedMcpTextResponse(
            result,
            maxResponseBytes,
            extra.requestId,
            signal
          );
        }, extra.signal);
      } catch (error) {
        // Typed, path-free errors for rejected or unresolvable revisions.
        if (
          error instanceof ToolipError &&
          (error.code === 'GIT_REVISION_INVALID' ||
            error.code === 'GIT_REVISION_NOT_FOUND')
        ) {
          return mcpFailure(
            error.code,
            error.message,
            maxResponseBytes,
            requestIdValue(extra.requestId)
          );
        }
        if (error instanceof McpBudgetError)
          return mcpFailure(
            error.code,
            error.message,
            maxResponseBytes,
            requestIdValue(extra.requestId)
          );
        return mcpFailure(
          'MCP_DIFF_FAILED',
          'Security diff failed; no clean result was issued.',
          maxResponseBytes,
          requestIdValue(extra.requestId)
        );
      }
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
