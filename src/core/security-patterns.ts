import type { ToolipFinding } from './report.js';

export type SecurityPattern = {
  id: string;
  title: string;
  category: string;
  severity: ToolipFinding['severity'];
  regex: RegExp;
  message: string;
  recommendation: string;
};

export const secretPatterns: SecurityPattern[] = [
  {
    id: 'TOOLIP-SECRET-GITHUB-TOKEN',
    title: 'GitHub token detected',
    category: 'secrets',
    severity: 'critical',
    regex: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
    message: 'A GitHub token-like secret was found.',
    recommendation:
      'Revoke the token, remove it from Git history, and store its replacement securely.'
  },
  {
    id: 'TOOLIP-SECRET-AWS-ACCESS-KEY',
    title: 'AWS access key detected',
    category: 'secrets',
    severity: 'critical',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    message: 'An AWS access key-like value was found.',
    recommendation:
      'Rotate the credential immediately and audit its usage.'
  },
  {
    id: 'TOOLIP-SECRET-PRIVATE-KEY',
    title: 'Private key detected',
    category: 'secrets',
    severity: 'critical',
    regex: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    message: 'Private key material was found.',
    recommendation:
      'Remove the key from the repository and rotate affected credentials.'
  },
  {
    id: 'TOOLIP-SECRET-NPM-TOKEN',
    title: 'npm token detected',
    category: 'secrets',
    severity: 'critical',
    regex: /\bnpm_[A-Za-z0-9]{20,}\b/g,
    message: 'An npm token-like value was found.',
    recommendation:
      'Rotate the token and store its replacement securely.'
  },
  {
    id: 'TOOLIP-SECRET-HARDCODED-PASSWORD',
    title: 'Hardcoded password detected',
    category: 'secrets',
    severity: 'high',
    regex: /\b(password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    message: 'A hardcoded password-like assignment was found.',
    recommendation:
      'Move passwords into environment variables or an encrypted secret manager.'
  },
  {
    id: 'TOOLIP-SECRET-JWT-SECRET',
    title: 'Hardcoded JWT secret detected',
    category: 'secrets',
    severity: 'high',
    regex: /\b(jwtSecret|JWT_SECRET|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]/g,
    message: 'A hardcoded JWT secret was found.',
    recommendation:
      'Load a strong random secret from a secure runtime source.'
  },
  {
    id: 'TOOLIP-SECRET-GENERIC-API-KEY',
    title: 'Generic API key detected',
    category: 'secrets',
    severity: 'medium',
    regex: /\b(apiKey|API_KEY|api_key)\s*[:=]\s*['"][A-Za-z0-9_-]{16,}['"]/g,
    message: 'A hardcoded API key-like value was found.',
    recommendation:
      'Remove API keys from source code and rotate exposed credentials.'
  }
];

export const dangerousCodePatterns: SecurityPattern[] = [
  {
    id: 'TOOLIP-DANGEROUS-EVAL',
    title: 'Dangerous eval usage',
    category: 'dangerous-code',
    severity: 'high',
    regex: /\beval\s*\(/g,
    message:
      'eval() can execute arbitrary code and introduce injection risk.',
    recommendation:
      'Replace eval() with explicit parsing or safe control flow.'
  },
  {
    id: 'TOOLIP-DANGEROUS-NEW-FUNCTION',
    title: 'Dangerous Function constructor usage',
    category: 'dangerous-code',
    severity: 'high',
    regex: /\bnew\s+Function\s*\(/g,
    message:
      'The Function constructor executes dynamic code.',
    recommendation:
      'Avoid runtime code generation and use explicit functions.'
  },
  {
    id: 'TOOLIP-DANGEROUS-CHILD-PROCESS-EXEC',
    title: 'Unsafe child_process exec usage',
    category: 'dangerous-code',
    severity: 'high',
    regex:
      /(?:\bchild_process\s*\.\s*exec|(?<![\w.])exec)\s*\(/g,
    message:
      'Shell execution may become unsafe when untrusted input reaches the command.',
    recommendation:
      'Prefer execFile() or spawn() with argument arrays and strict validation.'
  },
  {
    id: 'TOOLIP-DANGEROUS-EXECSYNC',
    title: 'Unsafe execSync usage',
    category: 'dangerous-code',
    severity: 'high',
    regex:
      /(?:\bchild_process\s*\.\s*execSync|(?<![\w.])execSync)\s*\(/g,
    message:
      'Synchronous shell execution can introduce injection and blocking risks.',
    recommendation:
      'Avoid shell execution or use safer process APIs with validated arguments.'
  }
];

export const configSecurityPatterns: SecurityPattern[] = [
  {
    id: 'TOOLIP-CONFIG-OPEN-CORS',
    title: 'Open CORS policy detected',
    category: 'configuration',
    severity: 'medium',
    regex: /\borigin\s*:\s*['"]\*['"]/g,
    message: 'CORS origin is configured as "*".',
    recommendation:
      'Restrict allowed origins to trusted domains.'
  },
  {
    id: 'TOOLIP-CONFIG-WEAK-JWT-SECRET',
    title: 'Weak JWT secret detected',
    category: 'configuration',
    severity: 'high',
    regex:
      /\b(jwtSecret|JWT_SECRET|jwt_secret)\s*[:=]\s*['"](secret|changeme|password|123456|devsecret)['"]/gi,
    message: 'A weak JWT secret was detected.',
    recommendation:
      'Use a long, random, high-entropy secret.'
  },
  {
    id: 'TOOLIP-CONFIG-LONG-JWT-EXPIRY',
    title: 'Long-lived JWT expiry detected',
    category: 'configuration',
    severity: 'medium',
    regex:
      /\b(expiresIn|JWT_EXPIRES_IN)\s*[:=]\s*['"](?:365d|999d|1000d|never|10y)['"]/gi,
    message: 'A long-lived JWT expiry was detected.',
    recommendation:
      'Use short-lived access tokens and refresh-token rotation.'
  }
];

export const securityHeaderNames = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options'
];
