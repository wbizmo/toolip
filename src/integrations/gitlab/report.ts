import { createHash } from 'node:crypto';
import path from 'node:path';
import type { ToolipReport, SerializedFinding } from '../../core/report.js';
import { redactSensitiveText } from '../../core/safe-output.js';

const maximumFindings = 50_000;
const severityNames = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info'
} as const;
const schemaVersion = '15.2.5';

/** A GitLab SAST report is not a substitute for the canonical Toolip report.
 * Findings without safe source coordinates are not silently assigned fake lines.
 */
export function toGitLabSastReport(report: ToolipReport) {
  if (report.tool !== 'toolip' || !Array.isArray(report.findings) ||
      report.findings.length > maximumFindings)
    throw new TypeError('GitLab adapter requires a bounded Toolip report.');
  const generated = Date.parse(report.generatedAt);
  if (!Number.isFinite(generated))
    throw new TypeError('GitLab adapter requires a valid scan timestamp.');
  const timestamp = new Date(generated).toISOString().slice(0, 19);
  const complete =
    report.analysis?.state === 'complete' &&
    report.analysis.reasons.length === 0 &&
    report.analysis.coverage?.state === 'complete' &&
    report.analysis.coverage.skipped === 0 &&
    report.analysis.coverage.failed === 0;
  const accepted: SerializedFinding[] = [];
  let omitted = 0;
  for (const item of report.findings) {
    if (
      !item ||
      typeof item.file !== 'string' ||
      item.file.length === 0 ||
      item.file.length > 2048 ||
      path.posix.isAbsolute(item.file) ||
      path.win32.isAbsolute(item.file) ||
      item.file.includes('\\') ||
      item.file.split('/').some((segment) => segment === '..') ||
      !Number.isSafeInteger(item.line) ||
      (item.line as number) < 1 ||
      !Object.hasOwn(severityNames, item.severity)
    ) {
      omitted += 1;
      continue;
    }
    accepted.push(item);
  }
  const vulns = accepted.map((item) => {
    const line = item.line as number;
    const id = createHash('sha256')
      .update(JSON.stringify([item.id, item.file, line]))
      .digest('hex');
    return {
      id,
      category: 'sast',
      name: redactSensitiveText(item.title).slice(0, 255),
      message: redactSensitiveText(item.message).slice(0, 4096),
      description: redactSensitiveText(item.message).slice(0, 8192),
      severity: severityNames[item.severity],
      confidence: 'Medium',
      scanner: { id: 'toolip', name: 'Toolip' },
      location: {
        file: item.file,
        start_line: line,
        end_line:
          Number.isSafeInteger(item.endLine) && (item.endLine as number) >= line
            ? item.endLine
            : line
      },
      identifiers: [{
        type: 'toolip_rule',
        name: redactSensitiveText(item.id).slice(0, 255),
        value: id.slice(0, 64)
      }]
    };
  });
  const warnings = [
    ...(!complete ? ['Toolip scan was incomplete or failed; this report is not an all-clear.'] : []),
    ...(omitted > 0 ? [
      `${omitted} Toolip finding(s) had no safe source location and were not mapped to SAST.`
    ] : [])
  ];
  return {
    version: schemaVersion,
    scan: {
      analyzer: {
        id: 'toolip', name: 'Toolip',
        url: 'https://github.com/wbizmo/toolip',
        vendor: { name: 'Zivora Labs' },
        version: report.version
      },
      scanner: {
        id: 'toolip', name: 'Toolip',
        url: 'https://github.com/wbizmo/toolip',
        vendor: { name: 'Zivora Labs' },
        version: report.version
      },
      type: 'sast',
      start_time: timestamp,
      end_time: timestamp,
      status: complete && omitted === 0 ? 'success' : 'failure',
      ...(warnings.length ? { messages: warnings.map((value) => ({
        level: 'warn',
        value
      })) } : {})
    },
    vulnerabilities: vulns,
    toolip: {
      analysisState: report.analysis?.state ?? 'unknown',
      reportedFindings: report.summary?.totalFindings ?? report.findings.length,
      mappedSastFindings: vulns.length,
      unmappedFindings: omitted,
      incomplete: !complete || omitted > 0,
      scope: 'source-location-findings-only'
    }
  };
}
