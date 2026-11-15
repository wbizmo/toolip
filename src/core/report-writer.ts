import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { ToolipReport } from './report.js';
import { createSarifReport } from './sarif.js';
import type { Finding } from '../contracts/finding.js';
import type { AnalysisState } from '../contracts/analysis.js';

const maximumReportBytes = 64 * 1024 * 1024 - 1;
const maximumReportNodes = 1_000_000;
const maximumReportFragments = 1_000_000;

function jsonStringBytes(value: string, maximumBytes: number): number {
  let bytes = 2;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (
      code === 0x22 ||
      code === 0x5c ||
      code === 0x08 ||
      code === 0x09 ||
      code === 0x0a ||
      code === 0x0c ||
      code === 0x0d
    )
      bytes += 2;
    else if (code < 0x20) bytes += 6;
    else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else bytes += 6;
    } else if (code >= 0xdc00 && code <= 0xdfff) bytes += 6;
    else if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else bytes += 3;
    if (bytes > maximumBytes) return bytes;
  }
  return bytes;
}

/** Serialize ordinary JSON data with bounded output and traversal work. */
export function serializeJsonOutputBounded(value: unknown): string {
  return serializeJsonOutputWithinBudget(value, maximumReportBytes);
}

/** Serializes JSON with an explicit output ceiling for generated artifacts. */
export function serializeJsonOutputWithinBudget(
  value: unknown,
  maximumBytes: number
): string {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > maximumReportBytes
  )
    throw new RangeError('JSON output budget must be from 1 byte to 64 MiB.');
  let nodes = 0;
  let bytes = 0;
  const ancestors = new WeakSet<object>();
  const append = (part: string, chunks: string[]): void => {
    bytes += Buffer.byteLength(part, 'utf8');
    if (bytes > maximumBytes || chunks.length >= maximumReportFragments)
      throw new RangeError('JSON output exceeds its configured budget.');
    chunks.push(part);
  };
  function* serialize(item: unknown, depth: number): Generator<string> {
    if (depth > 256 || ++nodes > maximumReportNodes)
      throw new RangeError('JSON output exceeds its traversal budget.');
    if (item === null) {
      yield 'null';
    } else if (typeof item === 'string') {
      if (jsonStringBytes(item, maximumBytes) > maximumBytes)
        throw new RangeError('JSON output exceeds its configured budget.');
      yield JSON.stringify(item);
    } else if (typeof item === 'number') {
      const encoded = Number.isFinite(item) ? JSON.stringify(item) : 'null';
      yield encoded ?? 'null';
    } else if (typeof item === 'boolean') {
      yield item ? 'true' : 'false';
    } else if (
      item === undefined ||
      typeof item === 'function' ||
      typeof item === 'symbol'
    ) {
      yield 'null';
    } else if (typeof item === 'bigint') {
      throw new TypeError('JSON output contains a BigInt value.');
    } else if (Array.isArray(item)) {
      if (ancestors.has(item))
        throw new TypeError('JSON output contains a cycle.');
      ancestors.add(item);
      try {
        yield '[';
        for (let index = 0; index < item.length; index += 1) {
          if (index > 0) yield ',';
          const descriptor = Object.getOwnPropertyDescriptor(
            item,
            String(index)
          );
          yield* serialize(
            descriptor && 'value' in descriptor ? descriptor.value : null,
            depth + 1
          );
        }
        yield ']';
      } finally {
        ancestors.delete(item);
      }
    } else if (typeof item === 'object') {
      if (ancestors.has(item))
        throw new TypeError('JSON output contains a cycle.');
      ancestors.add(item);
      try {
        yield '{';
        let first = true;
        for (const key in item) {
          if (!Object.hasOwn(item, key)) continue;
          if (nodes >= maximumReportNodes)
            throw new RangeError('JSON output exceeds its traversal budget.');
          const descriptor = Object.getOwnPropertyDescriptor(item, key);
          if (!descriptor?.enumerable || !('value' in descriptor))
            throw new TypeError('JSON output contains an accessor property.');
          const property = descriptor.value;
          if (
            property === undefined ||
            typeof property === 'function' ||
            typeof property === 'symbol'
          )
            continue;
          if (!first) yield ',';
          first = false;
          yield* serialize(key, depth + 1);
          yield ':';
          yield* serialize(property, depth + 1);
        }
        yield '}';
      } finally {
        ancestors.delete(item);
      }
    }
  }

  const chunks: string[] = [];
  for (const part of serialize(value, 0)) append(part, chunks);
  return chunks.join('');
}

export type ReportFormat = 'json' | 'md';

export function detectReportFormat(outputPath: string): ReportFormat {
  const extension = path.extname(outputPath).toLowerCase();

  if (extension === '.md' || extension === '.markdown') {
    return 'md';
  }

  return 'json';
}

export async function writeReport(
  outputPath: string,
  report: ToolipReport
): Promise<void> {
  const format = detectReportFormat(outputPath);

  if (format === 'md') {
    // Preflight the complete report before markdown rendering duplicates text.
    serializeJsonOutputBounded(report);
    const markdown = renderMarkdownReport(report);
    if (Buffer.byteLength(markdown, 'utf8') > maximumReportBytes)
      throw new RangeError('Markdown report exceeds its configured budget.');
    await writeFile(outputPath, markdown, 'utf8');
    return;
  }

  await writeFile(
    outputPath,
    `${serializeJsonOutputBounded(report)}\n`,
    'utf8'
  );
}

/** Writes a SARIF 2.1.0 view of the same sanitized findings and coverage state. */
export async function writeSarifReport(
  outputPath: string,
  input: {
    findings: readonly Finding[];
    analysisState: AnalysisState;
    toolVersion: string;
    policy?: {
      decision: string;
      policySha256: string;
      reasons?: readonly string[];
    };
  }
): Promise<void> {
  const sarif = createSarifReport(input);
  await writeFile(outputPath, `${serializeJsonOutputBounded(sarif)}\n`, 'utf8');
}

export function renderMarkdownReport(report: ToolipReport): string {
  const findings = report.findings.length
    ? report.findings
        .map((finding) => {
          const fileLine = finding.file ? `\n- File: \`${finding.file}\`` : '';
          const evidenceLine = finding.evidence
            ? `\n- Evidence: \`${finding.evidence}\``
            : '';

          return `### ${finding.title}

- ID: \`${finding.id}\`
- Severity: **${finding.severity.toUpperCase()}**
- Category: ${finding.category}${fileLine}${evidenceLine}

${finding.message}

**Recommendation:** ${finding.recommendation}
`;
        })
        .join('\n')
    : report.analysis && report.analysis.state !== 'complete'
      ? `No findings were reported, but the analysis was **${report.analysis.state.toUpperCase()}**, so this is not an all-clear.`
      : 'No findings were detected.';

  const coverage = report.analysis?.coverage;
  const coverageSection = coverage
    ? `\n- Eligible: ${coverage.eligible}\n- Scanned: ${coverage.scanned}\n- Skipped: ${coverage.skipped}\n- Failed: ${coverage.failed}\n- Excluded: ${coverage.excluded ?? 0}`
    : '';
  const analysisSection = report.analysis
    ? `\n## Analysis\n\n- State: **${report.analysis.state.toUpperCase()}**${report.analysis.reasons.map((reason) => `\n- ${reason}`).join('')}${coverageSection}\n`
    : '';

  return `# Toolip Report

Generated: ${report.generatedAt}

Root: \`${report.root}\`

Command: \`${report.command}\`

## Summary

| Severity | Count |
|---|---:|
| Critical | ${report.summary.critical} |
| High | ${report.summary.high} |
| Medium | ${report.summary.medium} |
| Low | ${report.summary.low} |
| Info | ${report.summary.info} |
| Total | ${report.summary.totalFindings} |
${analysisSection}
## Findings

${findings}
`;
}
