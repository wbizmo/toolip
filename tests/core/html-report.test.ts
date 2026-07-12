import { describe, expect, it } from 'vitest';
import { renderHtmlReport } from '../../src/core/publish/html.js';

describe('HTML report', () => {
  it('escapes finding content', () => {
    const html = renderHtmlReport({
      project: '<project>',
      generatedAt: '2026-01-01',
      findings: [{
        id: '1',
        title: '<script>alert(1)</script>',
        severity: 'high',
        category: 'test',
        message: 'test',
        recommendation: 'fix'
      }]
    });

    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });
});
