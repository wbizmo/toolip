import semver from 'semver';

/**
 * Minimum patched Node.js release per supported major (security/runtime-floors.json
 * is the reviewed source of truth; a test keeps both in sync).
 */
export const NODE_PATCH_FLOORS: Readonly<Record<number, string>> = {
  22: '22.23.4',
  24: '24.22.1'
};

export type RuntimeStatus =
  | { status: 'ok'; version: string }
  | { status: 'unsupported-major'; version: string; reason: string }
  | { status: 'unpatched'; version: string; floor: string; reason: string }
  | { status: 'invalid'; version: string; reason: string };

export const UNPATCHED_NODE_OVERRIDE = 'TOOLIP_ALLOW_UNPATCHED_NODE';

/**
 * Classifies a Node.js version string. O(1) time and space.
 * Unknown majors (including 23, 25+) are never treated as supported.
 */
export function assessNodeRuntime(rawVersion: string): RuntimeStatus {
  const version = semver.valid(rawVersion);

  if (!version) {
    return {
      status: 'invalid',
      version: rawVersion,
      reason: `Cannot parse Node.js version "${rawVersion}".`
    };
  }

  const floor = NODE_PATCH_FLOORS[semver.major(version)];

  if (!floor) {
    return {
      status: 'unsupported-major',
      version,
      reason: `Node.js ${version} is not a supported major. Use Node.js ${Object.values(NODE_PATCH_FLOORS).join(' or ')} or newer patch releases of those lines.`
    };
  }

  if (semver.lt(version, floor)) {
    return {
      status: 'unpatched',
      version,
      floor,
      reason: `Node.js ${version} predates the October 2026 security releases; ${floor} or newer is required for this line.`
    };
  }

  return { status: 'ok', version };
}

export type RuntimeDecision = {
  allow: boolean;
  warning?: string;
  error?: string;
};

/**
 * Decides whether a command may run. Unpatched or unsupported runtimes fail
 * closed unless the operator explicitly opts in, in which case a warning is
 * emitted. Informational invocations are always allowed so users can read the
 * message and upgrade.
 */
export function decideRuntimeAccess(
  assessment: RuntimeStatus,
  options: { informational: boolean; override: boolean }
): RuntimeDecision {
  if (assessment.status === 'ok') return { allow: true };

  const guidance =
    `${assessment.reason} Upgrading dependencies does not patch the Node.js binary; install a current patched release. ` +
    `Set ${UNPATCHED_NODE_OVERRIDE}=1 to run anyway at your own risk.`;

  if (options.informational) return { allow: true, warning: guidance };
  if (options.override) return { allow: true, warning: guidance };

  return { allow: false, error: guidance };
}
