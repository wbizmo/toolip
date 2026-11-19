import { access } from 'node:fs/promises';
import path from 'node:path';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import type { Finding, FindingSeverity } from '../../contracts/finding.js';
import { coverageOf } from '../../contracts/analysis.js';
import {
  isOmittedOnPlatform,
  readNpmDependencyInventory
} from '../../core/dependencies/inventory.js';
import { TextFileReader } from '../../core/text-file-reader.js';

const lifecycleNames = ['preinstall', 'install', 'postinstall'] as const;
const maximumManifestFiles = 20_000;
const maximumManifestBytes = 1024 * 1024;
const maximumAggregateManifestBytes = 32 * 1024 * 1024;
const maximumFindings = 10_000;

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
    message: 'The lifecycle script appears to perform network access.',
    remediation:
      'Review the remote destination and downloaded content before installation.'
  },
  {
    id: 'TLP-INSTALL-002',
    title: 'Shell execution in lifecycle script',
    severity: 'high',
    regex:
      /\b(sh|bash|zsh|cmd|powershell|pwsh)\b|child_process|execSync?\s*\(/i,
    message: 'The lifecycle script invokes a shell or child process.',
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

type ManifestPresence = 'present' | 'missing' | 'inaccessible';

/** Distinguishes a genuinely absent manifest from one we could not access. */
async function presence(filePath: string): Promise<ManifestPresence> {
  try {
    await access(filePath);
    return 'present';
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code === 'ENOENT' || code === 'ENOTDIR' ? 'missing' : 'inaccessible';
  }
}

export class InstallScriptAnalyzer implements Analyzer {
  readonly id = 'install-script-behavior';
  readonly version = '1.0.1';

  /** Inspects installed manifests and reports bounded lifecycle-script risks. */
  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const dependencies = await readNpmDependencyInventory(context.root);
    const manifestReader = new TextFileReader(
      {
        maxFiles: maximumManifestFiles,
        maxFileBytes: maximumManifestBytes,
        maxTotalBytes: maximumAggregateManifestBytes
      },
      { root: context.root, maxConcurrentReads: 1 }
    );

    const findings: Finding[] = [];
    let packagesInspected = 0;
    let lifecycleScripts = 0;
    // Lifecycle scripts can only be inspected for packages present on disk.
    // Anything else is unexamined, not clean.
    const notInspected: string[] = [];
    let notInspectedCount = 0;
    let failedCount = 0;
    let suppressedFindings = 0;
    // Optional packages npm legitimately omits (platform-specific) are out of
    // scope, not skipped: counting them would fail healthy projects.
    let excludedOptional = 0;

    for (let index = 0; index < dependencies.length; index += 1) {
      const dependency = dependencies[index];
      if (!dependency) continue;
      if (context.signal?.aborted) {
        throw new Error('Install-script analysis was cancelled.');
      }

      if (index >= maximumManifestFiles) {
        notInspectedCount += 1;
        if (notInspected.length < 5)
          notInspected.push(
            `${dependency.name}@${dependency.version} (manifest file budget reached)`
          );
        continue;
      }

      const manifestPath = path.join(
        context.root,
        ...dependency.installPath.split('/'),
        'package.json'
      );

      const manifestState = await presence(manifestPath);
      if (manifestState !== 'present') {
        // Excluded only when the lockfile proves npm omits it on this platform;
        // inaccessible or unproven-optional manifests stay unexamined.
        if (manifestState === 'missing' && isOmittedOnPlatform(dependency)) {
          excludedOptional += 1;
          continue;
        }
        notInspectedCount += 1;
        if (notInspected.length < 5)
          notInspected.push(
            `${dependency.name}@${dependency.version} (${manifestState === 'missing' ? 'not installed' : 'manifest not accessible'})`
          );
        continue;
      }

      const read = await manifestReader.read(manifestPath, context.signal);
      if (read.status !== 'ok') {
        if (read.status === 'cancelled')
          throw new Error('Install-script analysis was cancelled.');
        if (read.status === 'failed' || read.status === 'changed')
          failedCount += 1;
        else notInspectedCount += 1;
        if (notInspected.length < 5)
          notInspected.push(
            `${dependency.name}@${dependency.version} (manifest ${read.status})`
          );
        continue;
      }

      let manifest: PackageManifest;
      try {
        manifest = JSON.parse(read.content) as PackageManifest;
        if (
          !manifest ||
          typeof manifest !== 'object' ||
          Array.isArray(manifest)
        )
          throw new Error('manifest root is not an object');
      } catch {
        failedCount += 1;
        if (notInspected.length < 5)
          notInspected.push(
            `${dependency.name}@${dependency.version} (manifest is invalid)`
          );
        continue;
      }

      if (manifest.version && manifest.version !== dependency.version) {
        notInspectedCount += 1;
        if (notInspected.length < 5)
          notInspected.push(
            `${dependency.name}@${dependency.version} (installed version ${manifest.version} differs)`
          );
        continue;
      }

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

          if (findings.length >= maximumFindings) {
            suppressedFindings += 1;
            continue;
          }

          findings.push({
            id:
              `${signal.id}:${dependency.installPath}:` +
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
                summary: `${lifecycleName} script contains a potentially risky operation.`,
                fingerprint:
                  `${dependency.installPath}:${dependency.version}:` +
                  `${lifecycleName}:${signal.id}`
              }
            ],
            remediation: {
              summary: signal.remediation
            },
            metadata: {
              package: dependency.name,
              version: dependency.version,
              installPath: dependency.installPath,
              direct: dependency.direct,
              development: dependency.development,
              lifecycle: lifecycleName,
              commandRedacted: true
            }
          });
        }
      }
    }

    return {
      analyzer: this.id,
      durationMs: Math.round(performance.now() - startedAt),
      findings,
      coverage: (() => {
        const coverage = coverageOf({
          eligible: dependencies.length - excludedOptional,
          scanned: packagesInspected,
          skipped: notInspectedCount,
          failed: failedCount,
          excluded: excludedOptional
        });
        return suppressedFindings > 0 && coverage.state === 'complete'
          ? {
              ...coverage,
              state: 'partial' as const,
              reason: 'lifecycle-script finding output limit was reached'
            }
          : coverage;
      })(),
      warnings: [
        ...(notInspectedCount > 0
          ? [
              `${notInspectedCount} dependenc${notInspectedCount === 1 ? 'y was' : 'ies were'} not inspected${notInspected.length > 0 ? `, for example: ${notInspected.join(', ')}` : ''}. Install dependencies without running scripts (npm ci --ignore-scripts) to inspect them.`
            ]
          : []),
        ...(suppressedFindings > 0
          ? [
              `Lifecycle-script finding output limit reached; ${suppressedFindings} additional finding(s) were suppressed.`
            ]
          : [])
      ],
      metadata: {
        packagesInspected,
        lifecycleScripts,
        findings: findings.length,
        suppressedFindings
      }
    };
  }
}
