import type { Finding } from '../../contracts/finding.js';
import type { ToolipConfig } from './schema.js';

function wildcardMatch(
  value: string,
  pattern: string
): boolean {
  const escaped = pattern
    .replaceAll(/[.+^${}()|[\]\\]/g, '\\$&')
    .replaceAll('**', '___DOUBLE_STAR___')
    .replaceAll('*', '[^/]*')
    .replaceAll('___DOUBLE_STAR___', '.*');

  return new RegExp(`^${escaped}$`).test(value);
}

function suppressionActive(
  expiresAt?: string
): boolean {
  return (
    expiresAt === undefined ||
    new Date(expiresAt).getTime() > Date.now()
  );
}

export function applyFindingPolicy(
  findings: Finding[],
  config: ToolipConfig
): Finding[] {
  const output: Finding[] = [];

  for (const finding of findings) {
    const rule = config.rules[finding.ruleId];
    const file = finding.location?.file ?? '';

    if (rule?.enabled === false) {
      continue;
    }

    let severity =
      rule?.severity ?? finding.severity;

    for (const pathRule of rule?.paths ?? []) {
      if (
        file &&
        wildcardMatch(file, pathRule.pattern)
      ) {
        if (pathRule.enabled === false) {
          severity = finding.severity;
          break;
        }

        severity =
          pathRule.severity ?? severity;
      }
    }

    const suppressed = config.suppressions.some(
      (suppression) =>
        suppression.ruleId === finding.ruleId &&
        suppressionActive(
          suppression.expiresAt
        ) &&
        (
          suppression.path === undefined ||
          (
            file &&
            wildcardMatch(
              file,
              suppression.path
            )
          )
        )
    );

    if (suppressed) {
      continue;
    }

    output.push({
      ...finding,
      severity
    });
  }

  return output;
}
