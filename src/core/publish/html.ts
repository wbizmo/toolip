import type { ToolipFinding } from '../report.js';

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

export function renderHtmlReport(input: {
  project: string;
  generatedAt: string;
  findings: ToolipFinding[];
}): string {
  const rows = input.findings.map((finding) => `
    <tr>
      <td>${escapeHtml(finding.severity)}</td>
      <td>${escapeHtml(finding.title)}</td>
      <td>${escapeHtml(finding.file ?? '')}</td>
      <td>${escapeHtml(finding.recommendation)}</td>
    </tr>
  `).join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Toolip Security Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#111}
table{width:100%;border-collapse:collapse}
th,td{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}
th{background:#f5f5f5}
code{font-family:ui-monospace,monospace}
</style>
</head>
<body>
<h1>Toolip Security Report</h1>
<p><strong>Project:</strong> ${escapeHtml(input.project)}</p>
<p><strong>Generated:</strong> ${escapeHtml(input.generatedAt)}</p>
<p><strong>Findings:</strong> ${input.findings.length}</p>
<table>
<thead><tr><th>Severity</th><th>Finding</th><th>File</th><th>Recommendation</th></tr></thead>
<tbody>${rows}</tbody>
</table>
</body>
</html>`;
}
