import type { Command } from 'commander';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import { buildSecurityScorecard } from '../application/security-scorecard.js';
import { createProjectSnapshot } from '../application/project-snapshot.js';
import {
  loadTrustedOrganizationPolicy,
  parsePolicyAsCode,
  evaluatePolicyAsCode,
  mergePolicyLayers
} from '../core/policy-as-code.js';
import { sanitizeOutput } from '../core/safe-output.js';
import { writeSarifReport } from '../core/report-writer.js';
import { TOOLIP_VERSION } from '../config/version.js';
import type { FindingSeverity } from '../contracts/finding.js';

type PolicyCommandOptions = {
  path: string;
  file: string;
  organizationPolicy?: string;
  organizationPolicyPublicKey?: string;
  organizationPolicyKeyId?: string;
  organizationPolicyIssuer?: string;
  requireOrganizationPolicy?: boolean;
  offline?: boolean;
  allowPublicScope?: boolean;
  sarif?: string;
  failOn?: string;
  timeoutMs?: string;
};

function registerEvaluation(command: Command, explain: boolean): void {
  command
    .option('-p, --path <path>', 'Project path to evaluate.', process.cwd())
    .option(
      '-f, --file <file>',
      'Versioned YAML/JSON policy file.',
      '.toolip/policy.yaml'
    )
    .option(
      '--organization-policy <file>',
      'Optional signed organization policy envelope, stored outside the project.'
    )
    .option(
      '--organization-policy-public-key <file>',
      'Operator-configured Ed25519 public key for the organization policy signer.'
    )
    .option(
      '--organization-policy-key-id <id>',
      'Expected organization policy signing key ID.'
    )
    .option(
      '--organization-policy-issuer <issuer>',
      'Expected organization policy issuer identity.'
    )
    .option(
      '--require-organization-policy',
      'Fail closed if a trusted organization policy is not configured.'
    )
    .option('--offline', 'Disable registry and advisory network requests.')
    .option(
      '--fail-on <severity>',
      'Override the policy threshold: critical, high, medium, low, info.'
    )
    .option(
      '--timeout-ms <milliseconds>',
      'Bound the complete scorecard execution time.',
      '120000'
    )
    .option(
      '--allow-public-scope',
      'Consent to sending scoped npm package names to public providers.'
    )
    .option(
      '--sarif <file>',
      'Write policy findings and decision as SARIF 2.1.0.'
    )
    .action(async (options: PolicyCommandOptions) => {
      let failureDecision: 'incomplete' | 'misconfigured' | 'error' =
        'misconfigured';
      try {
        const allowedSeverities = new Set<FindingSeverity>([
          'critical',
          'high',
          'medium',
          'low',
          'info'
        ]);
        if (
          options.failOn &&
          !allowedSeverities.has(options.failOn as FindingSeverity)
        )
          throw new Error(
            '--fail-on must be critical, high, medium, low or info'
          );
        const timeoutMs = Number(options.timeoutMs ?? '120000');
        if (
          !Number.isSafeInteger(timeoutMs) ||
          timeoutMs < 1_000 ||
          timeoutMs > 600_000
        )
          throw new Error('--timeout-ms must be between 1000 and 600000');
        const projectSnapshot = await createProjectSnapshot(options.path);
        failureDecision = 'incomplete';
        const root = projectSnapshot.root;
        const policyPath = path.resolve(root, options.file);
        const canonicalPolicyPath = await realpath(policyPath);
        const policyRelative = path.relative(root, canonicalPolicyPath);
        if (
          path.isAbsolute(policyRelative) ||
          policyRelative === '..' ||
          policyRelative.startsWith(`..${path.sep}`)
        ) {
          throw new Error(
            'repository policy must stay inside the project root'
          );
        }
        const snapshotPolicyPath = policyRelative.split(path.sep).join('/');
        const policyFile = projectSnapshot.files.find(
          (file) => file.path === snapshotPolicyPath
        );
        if (policyFile?.content === undefined)
          throw new Error(
            'repository policy was not captured as bounded text in the project snapshot'
          );
        failureDecision = 'misconfigured';
        const loaded = parsePolicyAsCode(policyFile.content);
        const hasOrganizationTrustOption = Boolean(
          options.organizationPolicyPublicKey ||
          options.organizationPolicyKeyId ||
          options.organizationPolicyIssuer
        );
        if (options.requireOrganizationPolicy && !options.organizationPolicy)
          throw new Error(
            '--require-organization-policy requires --organization-policy'
          );
        let organization:
          Awaited<ReturnType<typeof loadTrustedOrganizationPolicy>> | undefined;
        if (options.organizationPolicy) {
          if (
            !options.organizationPolicyPublicKey ||
            !options.organizationPolicyKeyId ||
            !options.organizationPolicyIssuer
          )
            throw new Error(
              'organization policy requires an independently configured public key, key ID and issuer'
            );
          const organizationPath = await realpath(
            path.resolve(options.organizationPolicy)
          );
          const organizationRelative = path.relative(root, organizationPath);
          if (
            !path.isAbsolute(organizationRelative) &&
            (organizationRelative === '' ||
              (organizationRelative !== '..' &&
                !organizationRelative.startsWith(`..${path.sep}`)))
          ) {
            throw new Error(
              'organization policy must resolve outside the scanned project root'
            );
          }
          const publicKeyPath = await realpath(
            path.resolve(options.organizationPolicyPublicKey)
          );
          const keyRelative = path.relative(root, publicKeyPath);
          if (
            !path.isAbsolute(keyRelative) &&
            (keyRelative === '' ||
              (keyRelative !== '..' &&
                !keyRelative.startsWith(`..${path.sep}`)))
          ) {
            throw new Error(
              'organization policy trust key must resolve outside the scanned project root'
            );
          }
          organization = await loadTrustedOrganizationPolicy({
            filePath: organizationPath,
            publicKeyPath: options.organizationPolicyPublicKey,
            trustedKeyId: options.organizationPolicyKeyId,
            trustedIssuer: options.organizationPolicyIssuer
          });
        } else if (hasOrganizationTrustOption) {
          throw new Error(
            'organization policy trust options require --organization-policy'
          );
        }
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
          root,
          {},
          {
            projectSnapshot,
            offline: options.offline,
            allowPublicScope: options.allowPublicScope,
            budget: { totalMs: timeoutMs }
          }
        );
        const evaluation = evaluatePolicyAsCode({
          policy: effective.policy,
          trust: effective.trust,
          findings: scan.findings,
          analysisState: scan.analysis.state,
          minimumSeverity: options.failOn as FindingSeverity | undefined,
          coverage: {
            eligible: scan.coverage.eligible,
            scanned: scan.coverage.scanned
          }
        });
        if (options.sarif)
          await writeSarifReport(options.sarif, {
            findings: scan.findings,
            analysisState: scan.analysis.state,
            toolVersion: TOOLIP_VERSION,
            policy: {
              decision: evaluation.decision,
              policySha256: evaluation.policySha256,
              reasons: evaluation.reasons
            }
          });
        const output = {
          decision: evaluation.decision,
          decisionSha256: evaluation.policySha256,
          policy: {
            version: effective.policy.version,
            sourceSha256: loaded.sha256,
            organizationSha256: organization?.sha256,
            organizationIssuer: organization?.issuer,
            organizationKeyId: organization?.keyId,
            organizationIdentity: organization?.identity,
            organizationTrusted: effective.trust.trusted,
            ruleSets: effective.policy.ruleSets ?? ['all'],
            minimumCoverage: effective.policy.minimumCoverage
          },
          analysis: {
            state: scan.analysis.state,
            coverage: scan.coverage,
            reasons: scan.analysis.reasons
          },
          reasons: evaluation.reasons,
          findings: sanitizeOutput(
            (explain ? scan.findings : evaluation.findings).map((finding) => ({
              id: finding.id,
              ruleId: finding.ruleId,
              title: finding.title,
              severity: finding.severity,
              confidence: finding.confidence,
              message: finding.message,
              location: finding.location
            }))
          )
        };
        process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
        process.exitCode =
          evaluation.decision === 'pass'
            ? 0
            : evaluation.decision === 'fail'
              ? 2
              : evaluation.decision === 'incomplete'
                ? 3
                : 1;
      } catch (error) {
        const message =
          error instanceof Error && error.message.length < 256
            ? error.message
            : 'policy evaluation failed';
        process.stdout.write(
          `${JSON.stringify({ decision: failureDecision, reasons: [message] })}\n`
        );
        process.exitCode = failureDecision === 'incomplete' ? 3 : 1;
      }
    });
}

/** Registers deterministic, read-only policy check and explanation commands. */
export function registerPolicyCommand(program: Command): void {
  const policy = program
    .command('policy')
    .description('Validate, evaluate or explain versioned local scan policy.');
  registerEvaluation(
    policy
      .command('check')
      .description('Run a scan and evaluate the policy gate.'),
    false
  );
  registerEvaluation(
    policy
      .command('explain')
      .description('Explain policy decisions and all findings.'),
    true
  );
}
