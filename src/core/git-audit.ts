import { access } from 'node:fs/promises';
import path from 'node:path';
import { runGit } from './git/safe-git.js';
import type { Finding } from '../contracts/finding.js';
import {
  createScannerContext,
  type ScannerContext
} from './scanner-context.js';

export type GitAuditResult = {
  findings: Finding[];
  summary: {
    filesChecked: number;
    dangerousFiles: number;
    /** A .gitignore file exists (policy presence only; not proof of protection). */
    gitignorePresent: boolean;
    /** Observed with `git check-ignore`; false when not ignored OR unknown. */
    envIgnored: boolean;
    pemIgnored: boolean;
    /** `unknown` when the root is not a Git work tree: nothing is assumed protective. */
    ignoreStatus: 'observed' | 'unknown';
    trackedSensitiveFiles: number;
  };
};

const dangerousFilePatterns = [
  {
    id: 'ENV-FILE',
    regex: /(^|\/)\.env(\.|$|\/)?/i,
    title: '.env file present',
    severity: 'high' as const,
    message: 'A .env-style file exists in the project tree.',
    recommendation:
      'Keep .env files local, ensure they are ignored, and never commit real secrets.'
  },
  {
    id: 'PEM-FILE',
    regex: /\.pem$/i,
    title: 'PEM file present',
    severity: 'critical' as const,
    message: 'A PEM key file exists in the project tree.',
    recommendation:
      'Remove private key files from the repository and rotate affected credentials.'
  },
  {
    id: 'KEY-FILE',
    regex: /\.(key|p12|pfx)$/i,
    title: 'Key/certificate file present',
    severity: 'critical' as const,
    message: 'A key or certificate-like file exists in the project tree.',
    recommendation: 'Do not store key material in source repositories.'
  }
];

/** Example/template env files are meant to be committed. */
const safeTemplatePattern =
  /(^|\/)\.env\.(example|sample|template|dist|defaults)$/i;

/** Representative paths probed with Git's own matcher. */
const envProbePaths = ['.env', '.env.local', '.env.production'];
const pemProbePaths = ['server.pem', 'private.key'];

type GitObservation =
  | { available: false; reason: string }
  | {
      available: true;
      /** path -> ignoring rule, or null when Git would NOT ignore it. */
      ignored: Map<
        string,
        { source: string; line: string; pattern: string } | null
      >;
      tracked: string[];
    };

export async function runGitAudit(
  rootOrContext: string | ScannerContext
): Promise<GitAuditResult> {
  const context =
    typeof rootOrContext === 'string'
      ? await createScannerContext(rootOrContext)
      : rootOrContext;
  const relativePaths = context.files.map((file) => file.relativePath);
  const gitignorePath = path.join(context.root, '.gitignore');
  const gitignorePresent = await exists(gitignorePath);
  const findings: Finding[] = [];

  const dangerousPresent = relativePaths.filter(
    (file) =>
      !safeTemplatePattern.test(file) &&
      dangerousFilePatterns.some((pattern) => pattern.regex.test(file))
  );

  for (const file of dangerousPresent) {
    for (const pattern of dangerousFilePatterns) {
      if (!pattern.regex.test(file)) continue;

      findings.push({
        id: `TOOLIP-GIT-${pattern.id}-${file.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
        ruleId: `TOOLIP-GIT-${pattern.id}`,
        title: pattern.title,
        severity: pattern.severity,
        confidence: 'high',
        category: 'git-security',
        message: pattern.message,
        source: 'git-audit',
        location: { file },
        remediation: { summary: pattern.recommendation }
      });
    }
  }

  const observation = await observeGit(context.root, [
    ...envProbePaths,
    ...pemProbePaths,
    ...dangerousPresent
  ]);

  let envIgnored = false;
  let pemIgnored = false;
  let trackedSensitiveFiles = 0;

  if (!observation.available) {
    findings.push({
      ...gitFinding(
        'TOOLIP-GIT-STATUS-UNKNOWN',
        'Git ignore and tracked-file status unknown',
        'low',
        `Toolip could not observe Git state: ${observation.reason}. Whether sensitive files are ignored or already committed is unknown, and nothing is assumed to be protected.`,
        'Run the audit inside the repository work tree.'
      ),
      evidence: [
        {
          summary: `Observed: ${observation.reason}. Status is unknown, not safe.`
        }
      ]
    });
  } else {
    const ruleText = (probe: string): string => {
      const hit = observation.ignored.get(probe);
      return hit
        ? `matched by ${hit.source || '(rule)'}:${hit.line} pattern "${hit.pattern}"`
        : 'no ignoring rule applies';
    };
    const isIgnored = (probe: string): boolean => {
      const hit = observation.ignored.get(probe);
      return Boolean(hit && !hit.pattern.startsWith('!'));
    };

    const missingEnv = envProbePaths.filter((probe) => !isIgnored(probe));
    envIgnored =
      missingEnv.length === 0 &&
      dangerousPresent
        .filter((file) => /(^|\/)\.env/i.test(file))
        .every(isIgnored);
    pemIgnored = pemProbePaths.every(isIgnored);

    if (!envIgnored && (gitignorePresent || missingEnv.length > 0)) {
      const offender =
        missingEnv[0] ??
        dangerousPresent.find(
          (file) => /(^|\/)\.env/i.test(file) && !isIgnored(file)
        );
      findings.push({
        ...gitFinding(
          'TOOLIP-GIT-ENV-NOT-IGNORED',
          '.env files are not ignored by Git',
          'high',
          `Git reports that ${offender ?? '.env'} is not ignored (${ruleText(offender ?? '.env')}).`,
          'Add .env and .env.* to .gitignore (keeping a safe .env.example) and remove any negating "!" rule.'
        ),
        evidence: [
          {
            summary: `Observed with git check-ignore: ${offender ?? '.env'} ${ruleText(offender ?? '.env')}.`
          }
        ]
      });
    }

    if (!pemIgnored && gitignorePresent) {
      const offender =
        pemProbePaths.find((probe) => !isIgnored(probe)) ?? 'server.pem';
      findings.push({
        ...gitFinding(
          'TOOLIP-GIT-PEM-NOT-IGNORED',
          'PEM/key files are not ignored by Git',
          'medium',
          `Git reports that ${offender} is not ignored (${ruleText(offender)}).`,
          'Add *.pem and other key material patterns to .gitignore.'
        ),
        evidence: [
          {
            summary: `Observed with git check-ignore: ${offender} ${ruleText(offender)}.`
          }
        ]
      });
    }

    // Ignore rules do not protect files that are already tracked.
    for (const file of observation.tracked) {
      if (safeTemplatePattern.test(file)) continue;
      for (const pattern of dangerousFilePatterns) {
        if (!pattern.regex.test(file)) continue;
        trackedSensitiveFiles += 1;
        const critical = pattern.severity === 'critical';
        findings.push({
          id: `TOOLIP-GIT-TRACKED-${pattern.id}-${file.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
          ruleId: `TOOLIP-GIT-TRACKED-${pattern.id}`,
          title: 'Sensitive file is tracked by Git',
          severity: critical ? 'critical' : 'high',
          confidence: 'high',
          category: 'git-security',
          message: `${file} is tracked by Git. Ignore rules do not protect tracked files, so its contents are committed or about to be.`,
          source: 'git-audit',
          location: { file },
          evidence: [
            { summary: 'Observed with git ls-files: path is in the index.' }
          ],
          remediation: {
            summary:
              'Remove it from the index (git rm --cached), rotate any exposed credential and purge it from history if it was pushed.'
          }
        });
      }
    }
  }

  if (!gitignorePresent) {
    findings.push(
      gitFinding(
        'TOOLIP-GIT-MISSING-GITIGNORE',
        'Missing .gitignore',
        'medium',
        'No .gitignore file was found.',
        'Add a .gitignore file that excludes secrets, build output, dependencies, and local machine files.'
      )
    );
  }

  return {
    findings,
    summary: {
      filesChecked: context.files.length,
      dangerousFiles: dangerousPresent.length,
      gitignorePresent,
      envIgnored,
      pemIgnored,
      ignoreStatus: observation.available ? 'observed' : 'unknown',
      trackedSensitiveFiles
    }
  };
}

/**
 * Asks Git itself: `check-ignore --no-index` evaluates the real matcher
 * (precedence, negation, nested .gitignore files, global excludes) without
 * letting tracked status mask the rule, and `ls-files -z` lists tracked paths.
 * Complexity: two subprocesses; O(P + T) for P probes and T tracked paths.
 */
async function observeGit(
  root: string,
  probes: readonly string[]
): Promise<GitObservation> {
  const inside = await runGit(['rev-parse', '--is-inside-work-tree'], {
    cwd: root,
    timeoutMs: 10_000,
    maxBuffer: 1024
  }).catch(() => undefined);
  if (inside?.code !== 0 || inside.stdout.toString('utf8').trim() !== 'true') {
    return {
      available: false,
      reason:
        'the scanned path is not inside a Git work tree (or Git could not be run)'
    };
  }

  const unique = [...new Set(probes)];
  const ignored = new Map<
    string,
    { source: string; line: string; pattern: string } | null
  >();

  const check = await runGit(
    ['check-ignore', '--no-index', '-v', '-n', '-z', '--stdin'],
    {
      cwd: root,
      timeoutMs: 15_000,
      maxBuffer: 16 * 1024 * 1024,
      input: `${unique.join('\0')}\0`
    }
  ).catch((error: unknown) => error as Error);
  if (check instanceof Error) {
    return {
      available: false,
      reason: `git check-ignore could not complete (${check.message})`
    };
  }
  // Exit 0 = something ignored, 1 = nothing ignored; both are valid answers.
  if (check.code !== 0 && check.code !== 1) {
    return {
      available: false,
      reason: `git check-ignore failed (exit ${check.code})`
    };
  }
  const fields = check.stdout.toString('utf8').split('\0');
  for (let i = 0; i + 3 < fields.length; i += 4) {
    const [source, line, pattern, pathname] = fields.slice(i, i + 4) as [
      string,
      string,
      string,
      string
    ];
    ignored.set(pathname, source === '' ? null : { source, line, pattern });
  }

  const ls = await runGit(['ls-files', '-z', '--'], {
    cwd: root,
    maxBuffer: 64 * 1024 * 1024
  }).catch((error: unknown) => error as Error);
  if (ls instanceof Error) {
    return {
      available: false,
      reason: `git ls-files could not complete (${ls.message})`
    };
  }
  if (ls.code !== 0) {
    return {
      available: false,
      reason: `git ls-files failed (exit ${ls.code})`
    };
  }

  return {
    available: true,
    ignored,
    tracked: ls.stdout.toString('utf8').split('\0').filter(Boolean)
  };
}

function gitFinding(
  id: string,
  title: string,
  severity: Finding['severity'],
  message: string,
  recommendation: string
): Finding {
  return {
    id,
    ruleId: id,
    title,
    severity,
    confidence: 'high',
    category: 'git-security',
    message,
    source: 'git-audit',
    remediation: { summary: recommendation }
  };
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}
