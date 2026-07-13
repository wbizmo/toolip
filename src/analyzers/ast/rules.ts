import type {
  FindingConfidence,
  FindingSeverity
} from '../../contracts/finding.js';

export type AstSecurityRule = {
  id: string;
  title: string;
  category: 'dangerous-code';
  severity: FindingSeverity;
  confidence: FindingConfidence;
  message: string;
  remediation: string;
};

export const astSecurityRules = {
  eval: {
    id: 'TLP-AST-001',
    title: 'Dynamic eval execution',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'high',
    message:
      'eval() executes code from a string and can introduce code-injection vulnerabilities.',
    remediation:
      'Replace eval() with explicit parsing, validated dispatch, or a purpose-built interpreter.'
  },
  functionConstructor: {
    id: 'TLP-AST-002',
    title: 'Dynamic Function constructor',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'high',
    message:
      'The Function constructor creates executable code from strings.',
    remediation:
      'Use explicit functions and validated control flow instead of runtime code generation.'
  },
  childProcessExec: {
    id: 'TLP-AST-003',
    title: 'Shell execution with child_process.exec',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'high',
    message:
      'child_process.exec() invokes a shell and can become vulnerable when command input is not strictly controlled.',
    remediation:
      'Prefer execFile() or spawn() with argument arrays and validate every untrusted value.'
  },
  childProcessExecSync: {
    id: 'TLP-AST-004',
    title: 'Synchronous shell execution with child_process.execSync',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'high',
    message:
      'child_process.execSync() invokes a shell synchronously and can introduce injection and availability risks.',
    remediation:
      'Avoid shell interpolation. Prefer execFileSync() or spawnSync() with validated argument arrays.'
  }
} satisfies Record<string, AstSecurityRule>;
