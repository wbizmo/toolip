import {
  access,
  readFile
} from 'node:fs/promises';
import path from 'node:path';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import type {
  Finding,
  FindingSeverity
} from '../../contracts/finding.js';
import { readNpmDependencyInventory } from '../../core/dependencies/inventory.js';

const lifecycleNames = [
  'preinstall',
  'install',
  'postinstall'
] as const;

type PackageManifest = {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
};

type SuspiciousSignal = {
  id: string;
  title: string;
  severity: FindingSeverity;
  regex: RegExp;
  message: string;
  remediation: string;
};

const signals: SuspiciousSignal[] = [
  {
    id: 'TLP-INSTALL-001',
    title: 'Network access in lifecycle script',
    severity: 'high',
    regex:
      /\b(curl|wget|Invoke-WebRequest|fetch|axios|http\.get|https\.get)\b/i,
    message:
      'The lifecycle script appears to perform network access.',
    remediation:
      'Review the remote destination and downloaded content before installation.'
  },
  {
    id: 'TLP-INSTALL-002',
    title: 'Shell execution in lifecycle script',
    severity: 'high',
    regex:
      /\b(sh|bash|zsh|cmd|powershell|pwsh)\b|child_process|execSync?\s*\(/i,
    message:
      'The lifecycle script invokes a shell or child process.',
    remediation:
      'Confirm every command and argument is necessary and does not execute untrusted input.'
  },
  {
    id: 'TLP-INSTALL-003',
    title: 'Filesystem write or deletion in lifecycle script',
    severity: 'medium',
    regex:
      /\b(rm\s+-rf|del\s+\/|rmdir|chmod|chown|writeFile|appendFile|unlink|rename)\b/i,
    message:
      'The lifecycle script appears to modify or delete filesystem content.',
    remediation:
      'Confirm writes remain within the package boundary and cannot alter sensitive files.'
  },
  {
    id: 'TLP-INSTALL-004',
    title: 'Encoded or obfuscated lifecycle script',
    severity: 'high',
    regex:
      /\b(base64|atob|fromCharCode|Buffer\.from\([^)]*,\s*['"]base64['"]|eval\s*\()/i,
    message:
      'The lifecycle script contains encoding or dynamic execution indicators.',
    remediation:
      'Decode and review the complete payload before allowing the script to run.'
  },
  {
    id: 'TLP-INSTALL-005',
    title: 'Credential or environment inspection in lifecycle script',
    severity: 'medium',
    regex:
      /\b(process\.env|AWS_|GITHUB_TOKEN|NPM_TOKEN|HOME|USERPROFILE|SSH_AUTH_SOCK)\b/i,
    message:
      'The lifecycle script reads environment or credential-related values.',
    remediation:
      'Verify that the package does not exfiltrate or persist sensitive environment data.'
  }
];

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

export class InstallScriptAnalyzer implements Analyzer {
  readonly id = 'install-script-behavior';
  readonly version = '1.0.0';

  async analyze(
    context: AnalyzerContext
  ): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const dependencies =
      await readNpmDependencyInventory(context.root);

    const findings: Finding[] = [];
    let packagesInspected = 0;
    let lifecycleScripts = 0;

    for (const dependency of dependencies) {
      if (context.signal?.aborted) {
        throw new Error(
          'Install-script analysis was cancelled.'
        );
      }

      const manifestPath = path.join(
        context.root,
        'node_modules',
        ...dependency.name.split('/'),
        'package.json'
      );

      if (!(await exists(manifestPath))) {
        continue;
      }

      const manifest = JSON.parse(
        await readFile(manifestPath, 'utf8')
      ) as PackageManifest;

      packagesInspected += 1;

      for (const lifecycleName of lifecycleNames) {
        const command = manifest.scripts?.[lifecycleName];

        if (!command) {
          continue;
        }

        lifecycleScripts += 1;

        for (const signal of signals) {
          signal.regex.lastIndex = 0;

          if (!signal.regex.test(command)) {
            continue;
          }

          findings.push({
            id:
              `${signal.id}:${dependency.name}:` +
              `${dependency.version}:${lifecycleName}`,
            ruleId: signal.id,
            title: signal.title,
            category: 'install-script',
            severity: signal.severity,
            confidence: 'medium',
            message:
              `${dependency.name}@${dependency.version} ` +
              `defines ${lifecycleName}: ${signal.message}`,
            source: 'package-manifest',
            evidence: [
              {
                summary:
                  `${lifecycleName}: ${command.slice(0, 240)}`,
                fingerprint:
                  `${dependency.name}@${dependency.version}:` +
                  `${lifecycleName}:${signal.id}`
              }
            ],
            remediation: {
              summary: signal.remediation
            },
            metadata: {
              package: dependency.name,
              version: dependency.version,
              direct: dependency.direct,
              development: dependency.development,
              lifecycle: lifecycleName,
              command
            }
          });
        }
      }
    }

    return {
      analyzer: this.id,
      durationMs: Math.round(
        performance.now() - startedAt
      ),
      findings,
      metadata: {
        packagesInspected,
        lifecycleScripts,
        findings: findings.length
      }
    };
  }
}
