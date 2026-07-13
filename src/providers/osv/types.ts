export type OsvQuery = {
  package: { ecosystem: 'npm'; name: string };
  version: string;
};

export type OsvVulnerability = {
  id: string;
  aliases?: string[];
  summary?: string;
  published?: string;
  modified?: string;
  severity?: Array<{ type?: string; score?: string }>;
  references?: Array<{ type?: string; url?: string }>;
  affected?: Array<{
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
  database_specific?: Record<string, unknown>;
};

export type OsvBatchResponse = {
  results: Array<{ vulns?: OsvVulnerability[] }>;
};
