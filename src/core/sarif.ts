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

function safeArtifactUri(file: string): string | undefined {
  const normalized = file.replaceAll('\\', '/');
  if (
    normalized.length === 0 ||
    normalized.length > 4_096 ||
    normalized.startsWith('/') ||
    /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(normalized) ||
    containsControlCharacters(normalized) ||
    redactSensitiveText(normalized) !== normalized
  )
    return undefined;
  const segments = normalized.split('/');
  if (
    segments.some(
      (segment) => segment === '' || segment === '.' || segment === '..'
    )
  )
    return undefined;
  try {
    return segments.map((segment) => encodeURIComponent(segment)).join('/');
  } catch {
    return undefined;
  }
}

function containsControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

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
  let invalidRuleIdCount = 0;
  let invalidArtifactLocationCount = 0;
  const fingerprintOccurrences = new Map<string, number>();
  const results = input.findings.map((finding) => {
    const ruleId = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u.test(finding.ruleId)
      ? finding.ruleId
      : 'TOOLIP-INVALID-RULE-ID';
    if (ruleId !== finding.ruleId) invalidRuleIdCount++;
    rules.set(ruleId, {
      id: ruleId,
      shortDescription: { text: redactSensitiveText(finding.title) },
      help: {
        text: redactSensitiveText(
          finding.remediation?.summary ?? finding.message
        )
      }
    });
    const locations: SarifLocation[] = [];
    const artifactUri = finding.location?.file
      ? safeArtifactUri(finding.location.file)
      : undefined;
    if (finding.location?.file) {
      if (!artifactUri) invalidArtifactLocationCount++;
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
      if (artifactUri)
        locations.push({
          physicalLocation: {
            artifactLocation: { uri: artifactUri },
            ...(region ? { region } : {})
          }
        });
    }
    // Fingerprint omits source line so ordinary line movement preserves identity.
    const stableIdentity = [
      ruleId,
      artifactUri ?? '',
      finding.location?.column ?? 0,
      finding.category,
      finding.evidence?.[0]?.fingerprint ?? finding.title
    ].join('\0');
    const occurrence = fingerprintOccurrences.get(stableIdentity) ?? 0;
    fingerprintOccurrences.set(stableIdentity, occurrence + 1);
    const stable = createHash('sha256')
      .update(`${stableIdentity}\0${occurrence}`)
      .digest('hex');
    const level =
      finding.severity === 'critical' || finding.severity === 'high'
        ? 'error'
        : finding.severity === 'medium'
          ? 'warning'
          : 'note';
    return {
      ruleId,
      level,
      message: { text: redactSensitiveText(finding.message) },
      ...(locations.length ? { locations } : {}),
      partialFingerprints: { 'toolip/v1': stable },
      properties: {
        confidence: finding.confidence,
        category: finding.category,
        ...(finding.location?.file && !locations.length
          ? { locationOmitted: true }
          : {})
      }
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
            executionSuccessful:
              input.analysisState === 'complete' &&
              invalidRuleIdCount === 0 &&
              invalidArtifactLocationCount === 0,
            properties: {
              analysisState:
                invalidRuleIdCount > 0 || invalidArtifactLocationCount > 0
                  ? 'failed'
                  : input.analysisState,
              ...(invalidRuleIdCount > 0 ? { invalidRuleIdCount } : {}),
              ...(invalidArtifactLocationCount > 0
                ? { invalidArtifactLocationCount }
                : {}),
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
