import { createHash } from 'node:crypto';
import path from 'node:path';
import type { SerializedFinding, ToolipReport } from '../../core/report.js';
import { redactSensitiveText } from '../../core/safe-output.js';

const maxAnnotations = 10_000;

function safeLocation(item: SerializedFinding): { path: string; line: number } | undefined {
  const name = item.file;
  if (
    typeof name !== 'string' ||
    !name || name.length > 2048 ||
    path.posix.isAbsolute(name) ||
    path.win32.isAbsolute(name) ||
    name.includes('\\') ||
    name.split('/').some((part) => part === '..') ||
    !Number.isSafeInteger(item.line) ||
    (item.line as number) < 1
  ) return undefined;
  return { path: name, line: item.line as number };
}

function azureEscape(value: string): string {
  // Prevent Azure DevOps logging-command injection via data in scanned code.
  return value
    .replaceAll('%', '%AZP25')
    .replaceAll('\r', '%0D')
    .replaceAll('\n', '%0A')
    .replaceAll(']', '%5D')
    .replaceAll(';', '%3B');
}

function safeMessage(value: string, limit = 1024): string {
  return redactSensitiveText(value).slice(0, limit);
}

/** Builds the exact Azure Pipelines logging commands without shell execution. */
export function toAzureLoggingCommands(report: ToolipReport): string[] {
  if (!Array.isArray(report.findings) || report.findings.length > maxAnnotations)
    throw new RangeError('Azure annotation input exceeds bounded limit.');
  const commands: string[] = [];
  const complete = report.analysis?.state === 'complete' &&
    report.analysis.coverage?.state === 'complete' &&
    report.analysis.coverage.skipped === 0 &&
    report.analysis.coverage.failed === 0;
  if (!complete)
    commands.push(
      '##vso[task.logissue type=error;code=TOOLIP_INCOMPLETE]' +
      'Toolip scan is incomplete or missing authoritative coverage'
    );
  for (const finding of report.findings) {
    const location = safeLocation(finding);
    if (!location) continue;
    const severity = finding.severity === 'critical' || finding.severity === 'high'
      ? 'error' : 'warning';
    const code = safeMessage(finding.id, 128).replace(/[^A-Za-z0-9._-]/gu, '_');
    commands.push(
      `##vso[task.logissue type=${severity};sourcepath=${azureEscape(location.path)};linenumber=${location.line};code=${code}]${azureEscape(safeMessage(finding.title))}`
    );
  }
  return commands;
}

/** Bitbucket Code Insights-compatible annotations; caller must authorize
 * any API upload separately. No repository token or source bytes are emitted.
 */
export function toBitbucketAnnotations(report: ToolipReport) {
  if (!Array.isArray(report.findings) || report.findings.length > maxAnnotations)
    throw new RangeError('Bitbucket annotation input exceeds bounded limit.');
  const annotations = [];
  let skipped = 0;
  for (const finding of report.findings) {
    const location = safeLocation(finding);
    if (!location) {
      skipped += 1;
      continue;
    }
    const id = createHash('sha256')
      .update(JSON.stringify([finding.id, location.path, location.line]))
      .digest('hex');
    annotations.push({
      external_id: id,
      annotation_type:
        finding.severity === 'critical' || finding.severity === 'high'
          ? 'VULNERABILITY' : 'CODE_SMELL',
      summary: safeMessage(finding.title, 255),
      details: safeMessage(finding.message, 2048),
      path: location.path,
      line: location.line
    });
  }
  const coverage = report.analysis?.coverage;
  const complete =
    report.analysis?.state === 'complete' &&
    coverage?.state === 'complete' &&
    coverage.scanned === coverage.eligible &&
    coverage.skipped === 0 &&
    coverage.failed === 0;
  return {
    schema: 'toolip.dev/bitbucket-annotations/v1',
    result: complete && skipped === 0 ? 'complete' : 'incomplete',
    totalFindings: report.findings.length,
    mappedFindings: annotations.length,
    unmappedFindings: skipped,
    annotations
  };
}
