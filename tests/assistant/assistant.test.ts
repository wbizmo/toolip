import { describe, expect, it, vi } from 'vitest';
import {
  explainFinding, explainFindingLocally, openAiAssistantProvider
} from '../../src/assistant/index.js';
import type { SerializedFinding } from '../../src/core/report.js';

const finding: SerializedFinding = {
  id: 'TLP-TEST-1',
  category: 'security',
  severity: 'high',
  title: 'Untrusted input reaches sensitive sink',
  message: 'Possible unsafe operation.',
  recommendation: 'Validate trusted inputs.',
  file: '/private/customer/repository/a.ts',
  evidence: 'GITHUB_TOKEN=abcde_secret'
};

describe('opt-in security assistant', () => {
  it('remains completely local when no network consent is provided', async () => {
    const explain = vi.fn(async () => 'remote advice');
    const local = await explainFinding(finding, {
      provider: { name: 'openai', explain },
      model: 'gpt-6'
    });
    expect(local.provider).toBe('local');
    expect(local.isVerified).toBe(false);
    expect(local.applied).toBe(false);
    expect(explain).not.toHaveBeenCalled();
  });

  it('sends only bounded redacted rule metadata when online is explicit', async () => {
    let input = '';
    const advice = await explainFinding(finding, {
      networkConsent: true,
      model: 'gpt-6',
      provider: {
        name: 'openai',
        async explain(context) {
          input = context;
          return 'Review the risk and validate input.';
        }
      }
    });
    expect(advice.provider).toBe('openai');
    expect(advice.isVerified).toBe(false);
    expect(advice.applied).toBe(false);
    expect(input).not.toContain('/private/customer');
    expect(input).not.toContain('GITHUB_TOKEN');
    expect(input).not.toContain('abcde_secret');
    expect(input).toContain('TLP-TEST-1');
  });

  it('rejects online AI without explicit model/provider', async () => {
    await expect(explainFinding(finding, {
      networkConsent: true
    })).rejects.toThrow('explicit provider and model');
  });

  it('posts to a fixed Responses endpoint without exposing source content or using tools', async () => {
    const fetcher = vi.fn(async (url: string | URL | Request, options?: RequestInit) => {
      expect(String(url)).toBe('https://api.openai.com/v1/responses');
      expect(options?.redirect).toBe('error');
      const request = JSON.parse(String(options?.body));
      expect(request.store).toBe(false);
      expect(request.tools).toEqual([]);
      expect(JSON.stringify(request)).not.toContain('/private/customer');
      return new Response(JSON.stringify({
        status: 'completed',
        output: [{
          type: 'message',
          content: [{ type: 'output_text', text: 'Review this issue.' }]
        }]
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
    const provider = openAiAssistantProvider('test-api-key-123', fetcher as typeof fetch);
    const advice = await explainFinding(finding, {
      networkConsent: true, model: 'gpt-6', provider
    });
    expect(advice.explanation).toBe('Review this issue.');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('never upgrades local remediation text to a validated fix', () => {
    const advice = explainFindingLocally(finding);
    expect(advice.proposedRemediation).toBe('Validate trusted inputs.');
    expect(advice.isVerified).toBe(false);
    expect(advice.applied).toBe(false);
  });
});
