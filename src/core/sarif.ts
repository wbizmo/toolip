import { createHash } from 'node:crypto';
import type { Finding } from '../contracts/finding.js';
import { redactSensitiveText, sanitizeOutput } from './safe-output.js';

type SarifLocation = {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: {
      startLine: number;
      startColumn?: number;
      endLine?: number;
      endColumn?: number;
    };
  };
};

/** Creates deterministic SARIF 2.1.0 without leaking finding evidence/secrets. */
export function createSarifReport(input: {
  findings: readonly Finding[];
  analysisState: 'complete' | 'partial' | 'failed';
  toolVersion: string;
  policy?: {
    decision: string;
    policySha256: string;
    reasons?: readonly string[];
  };
}): Record<string, unknown> {
  const rules = new Map<
    string,
    { id: string; shortDescription: { text: string }; help: { text: string } }
  >();
  const results = input.findings.map((finding) => {
    rules.set(finding.ruleId, {
      id: finding.ruleId,
      shortDescription: { text: redactSensitiveText(finding.title) },
      help: {
        text: redactSensitiveText(
          finding.remediation?.summary ?? finding.message
        )
      }
    });
    const locations: SarifLocation[] = [];
    if (finding.location?.file) {
      const region =
        finding.location.line && finding.location.line > 0
          ? {
              startLine: finding.location.line,
              ...(finding.location.column
                ? { startColumn: finding.location.column }
                : {}),
              ...(finding.location.endLine
                ? { endLine: finding.location.endLine }
                : {}),
              ...(finding.location.endColumn
                ? { endColumn: finding.location.endColumn }
                : {})
            }
          : undefined;
      locations.push({
        physicalLocation: {
          artifactLocation: {
            uri: finding.location.file.replaceAll('\\', '/')
          },
          ...(region ? { region } : {})
        }
      });
    }
    // Fingerprint omits source line so ordinary line movement preserves identity.
    const stable = createHash('sha256')
      .update(
        `${finding.ruleId}\0${finding.location?.file ?? ''}\0${finding.category}\0${finding.evidence?.[0]?.fingerprint ?? finding.title}`
      )
      .digest('hex');
    const level =
      finding.severity === 'critical' || finding.severity === 'high'
        ? 'error'
        : finding.severity === 'medium'
          ? 'warning'
          : 'note';
    return {
      ruleId: finding.ruleId,
      level,
      message: { text: redactSensitiveText(finding.message) },
      ...(locations.length ? { locations } : {}),
      partialFingerprints: { 'toolip/v1': stable },
      properties: { confidence: finding.confidence, category: finding.category }
    };
  });
  return sanitizeOutput({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Toolip',
            semanticVersion: input.toolVersion,
            rules: [...rules.values()].sort((a, b) => a.id.localeCompare(b.id))
          }
        },
        results,
        invocations: [
          {
            executionSuccessful: input.analysisState === 'complete',
            properties: {
              analysisState: input.analysisState,
              ...(input.policy
                ? {
                    policyDecision: input.policy.decision,
                    policySha256: input.policy.policySha256,
                    policyReasons: input.policy.reasons ?? []
                  }
                : {})
            }
          }
        ]
      }
    ]
  });
}
