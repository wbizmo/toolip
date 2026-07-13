import type {
  FindingConfidence,
  FindingSeverity
} from './finding.js';

export type RuleDefinition = {
  id: string;
  title: string;
  category: string;
  defaultSeverity: FindingSeverity;
  defaultConfidence: FindingConfidence;
  description: string;
  remediation: string;
  references?: string[];
};

const RULE_ID_PATTERN = /^TLP-[A-Z]+-\d{3}$/;

export function assertValidRuleId(ruleId: string): void {
  if (!RULE_ID_PATTERN.test(ruleId)) {
    throw new Error(
      `Invalid Toolip rule ID "${ruleId}". Expected format: TLP-CATEGORY-001.`
    );
  }
}
