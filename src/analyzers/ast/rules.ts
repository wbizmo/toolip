import type {
  FindingConfidence,
  FindingSeverity
} from '../../contracts/finding.js';

export type AstSecurityRule = {
  id: string;
  title: string;
  category: 'dangerous-code' | 'authorization' | 'sensitive-data' | 'concurrency';
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
    message: 'The Function constructor creates executable code from strings.',
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
  },
  sqlInjection: {
    id: 'TLP-AST-005',
    title: 'Request data reaches a SQL query sink',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'medium',
    message:
      'Request-derived data reaches a query argument. Use parameterized values and validate dynamic identifiers.',
    remediation:
      'Pass user values through the database driver’s parameter binding API; allowlist any dynamic table or column names.'
  },
  serverSideRequestForgery: {
    id: 'TLP-AST-006',
    title: 'Request data reaches an outbound URL sink',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'medium',
    message:
      'Request-derived data reaches an outbound HTTP URL argument and may enable server-side request forgery.',
    remediation:
      'Resolve destinations against an explicit host allowlist and reject loopback, link-local, private, and disallowed redirect targets.'
  },
  unsafeFilePath: {
    id: 'TLP-AST-009',
    title: 'Request data reaches a filesystem path sink',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'medium',
    message:
      'Request-derived data reaches a filesystem operation. A caller may escape an intended directory or access an unintended file unless canonical containment and link-safe access are enforced.',
    remediation:
      'Resolve the candidate beneath a trusted root, verify canonical containment, and use no-follow or handle-based access where supported.'
  },
  commandInjection: {
    id: 'TLP-AST-010',
    title: 'Request data reaches a shell command',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'medium',
    message:
      'Request-derived data reaches a child-process API that invokes a shell and may change the executed command.',
    remediation:
      'Avoid shell command strings. Use execFile or spawn with a fixed executable and validated argument array, leaving shell disabled.'
  },
  dynamicCommandExecution: {
    id: 'TLP-AST-011',
    title: 'Request data reaches a dynamic child-process method',
    category: 'dangerous-code',
    severity: 'medium',
    confidence: 'low',
    message:
      'Request-derived data reaches a dynamically selected child-process method; the scanner cannot determine whether it invokes a shell.',
    remediation:
      'Select a fixed child-process API and executable. Keep shell execution disabled and validate each argument.'
  },
  unsafeDeserialization: {
    id: 'TLP-AST-012',
    title: 'Untrusted data reaches node-serialize unserialize',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'high',
    message:
      'Request-derived data reaches node-serialize unserialize(), which can construct executable values from serialized input.',
    remediation:
      'Remove node-serialize unserialize() for untrusted input. Use a data-only format with a safe schema and validate the decoded structure before use.'
  },
  crossSiteScripting: {
    id: 'TLP-AST-007',
    title: 'Request data reaches an HTML injection sink',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'medium',
    message:
      'Request-derived data reaches an HTML-writing API without visible contextual encoding.',
    remediation:
      'Use framework escaping or a context-aware HTML sanitizer before writing untrusted values to an HTML sink.'
  },
  prototypePollution: {
    id: 'TLP-AST-008',
    title: 'Request data reaches a prototype mutation sink',
    category: 'dangerous-code',
    severity: 'high',
    confidence: 'medium',
    message:
      'Request-derived keys or objects reach a prototype-sensitive mutation operation.',
    remediation:
      'Reject prototype-related keys, use null-prototype dictionaries, and copy only explicitly allowed properties.'
  },
  sensitiveDataExposure: {
    id: 'TLP-DATA-001',
    title: 'Sensitive data reaches an output or storage sink',
    category: 'sensitive-data',
    severity: 'high',
    confidence: 'medium',
    message:
      'A credential-like environment value may flow into a logging, telemetry, response, network, or persistence sink.',
    remediation:
      'Keep credentials out of logs and responses, and store only the minimum required sensitive data using the application’s approved protection controls. Pass secrets only to trusted clients and use approved redaction for diagnostics.'
  },
  filesystemTimeOfCheckTimeOfUse: {
    id: 'TLP-RACE-001',
    title: 'Filesystem check followed by a separate path operation',
    category: 'concurrency',
    severity: 'medium',
    confidence: 'low',
    message:
      'The same path is checked and later used in a separate filesystem operation, allowing a concurrent replacement between the calls.',
    remediation:
      'Open once with restrictive no-follow and atomic flags, then operate through the resulting handle.'
  },
  nonAtomicReadCheckWrite: {
    id: 'TLP-RACE-002',
    title: 'Read-check-write sequence without a visible atomic predicate',
    category: 'concurrency',
    severity: 'medium',
    confidence: 'low',
    message:
      'A value is read, checked, then mutated without a visible compare-and-swap or version predicate.',
    remediation:
      'Move the state predicate into an atomic conditional update, compare a version, or use an isolation mechanism that prevents competing updates.'
  }
} satisfies Record<string, AstSecurityRule>;
