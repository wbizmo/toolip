export type LearnTopic = {
  id: string;
  title: string;
  explanation: string;
  risks: string[];
  mistakes: string[];
  secureExamples: string[];
  bestPractices: string[];
};

const topics: Record<string, LearnTopic> = {
  cors: {
    id: 'cors',
    title: 'CORS Security',
    explanation: 'CORS controls which origins can access browser-protected resources from your API.',
    risks: [
      'Overly broad origins can expose APIs to untrusted frontends.',
      'Credentials with wildcard origins can create serious access-control mistakes.'
    ],
    mistakes: [
      'Using origin: "*" for authenticated APIs.',
      'Using the same CORS policy in development and production.'
    ],
    secureExamples: [
      'Allow only https://yourdomain.com in production.',
      'Use environment-specific allowed origin lists.'
    ],
    bestPractices: [
      'Avoid wildcard origins for sensitive APIs.',
      'Review CORS together with cookies, credentials, and authentication.'
    ]
  },
  jwt: {
    id: 'jwt',
    title: 'JWT Security',
    explanation: 'JWTs are signed tokens used to represent claims, identity, and authorization context.',
    risks: [
      'Weak secrets allow token forgery.',
      'Long-lived tokens increase impact after theft.'
    ],
    mistakes: [
      'Using "secret" or "password" as the JWT secret.',
      'Setting access tokens to last for months or years.'
    ],
    secureExamples: [
      'Use a long random secret from a secret manager.',
      'Use short access-token lifetimes with refresh-token rotation.'
    ],
    bestPractices: [
      'Validate issuer, audience, signature, and expiry.',
      'Never store JWT secrets in source code.'
    ]
  },
  xss: {
    id: 'xss',
    title: 'Cross-Site Scripting',
    explanation: 'XSS happens when untrusted input is rendered as executable browser code.',
    risks: [
      'Session theft.',
      'Account takeover.',
      'Malicious actions performed as the user.'
    ],
    mistakes: [
      'Rendering raw HTML from users.',
      'Trusting sanitized content without context-aware escaping.'
    ],
    secureExamples: [
      'Escape output by default.',
      'Use CSP to reduce script execution risk.'
    ],
    bestPractices: [
      'Avoid dangerous HTML injection APIs.',
      'Sanitize rich text with a trusted sanitizer.'
    ]
  },
  csrf: {
    id: 'csrf',
    title: 'Cross-Site Request Forgery',
    explanation: 'CSRF tricks a logged-in browser into sending unwanted authenticated requests.',
    risks: [
      'Unauthorized state changes.',
      'Account setting changes.',
      'Financial or administrative actions triggered silently.'
    ],
    mistakes: [
      'Relying only on cookies for authentication.',
      'Not using SameSite cookie settings.'
    ],
    secureExamples: [
      'Use SameSite=Lax or SameSite=Strict cookies.',
      'Use CSRF tokens for sensitive state-changing requests.'
    ],
    bestPractices: [
      'Require explicit anti-CSRF protection for cookie-authenticated apps.',
      'Avoid GET requests for state-changing operations.'
    ]
  },
  secrets: {
    id: 'secrets',
    title: 'Secrets Management',
    explanation: 'Secrets are credentials such as API keys, tokens, passwords, and private keys.',
    risks: [
      'Committed secrets can be copied forever from Git history.',
      'Leaked credentials can grant attackers access to production systems.'
    ],
    mistakes: [
      'Storing secrets in .env files committed to Git.',
      'Hardcoding API keys in source files.'
    ],
    secureExamples: [
      'Use environment variables or encrypted local vaults.',
      'Rotate credentials after exposure.'
    ],
    bestPractices: [
      'Keep .env files ignored.',
      'Commit only safe .env.example files.',
      'Scan before committing.'
    ]
  },
  auth: {
    id: 'auth',
    title: 'Authentication and Authorization',
    explanation: 'Authentication verifies identity; authorization decides what that identity can access.',
    risks: [
      'Broken access control.',
      'Privilege escalation.',
      'Session compromise.'
    ],
    mistakes: [
      'Checking only if a user is logged in.',
      'Trusting client-side roles.'
    ],
    secureExamples: [
      'Check permissions on the server for every protected action.',
      'Use least privilege access rules.'
    ],
    bestPractices: [
      'Separate authentication from authorization.',
      'Log sensitive access and permission changes.'
    ]
  },
  dependencies: {
    id: 'dependencies',
    title: 'Dependency Security',
    explanation: 'Dependency security is about managing risk from third-party packages.',
    risks: [
      'Deprecated packages may stop receiving fixes.',
      'Typosquatted packages can impersonate popular libraries.',
      'Transitive dependencies can introduce hidden risk.'
    ],
    mistakes: [
      'Installing packages without checking maintainers.',
      'Ignoring deprecated package warnings.',
      'Allowing dependency bloat.'
    ],
    secureExamples: [
      'Inspect package health before adoption.',
      'Prefer maintained packages with active releases.'
    ],
    bestPractices: [
      'Review lockfile changes.',
      'Use small dependency surfaces.',
      'Replace abandoned packages early.'
    ]
  }
};

export function listLearnTopics(): LearnTopic[] {
  return Object.values(topics);
}

export function getLearnTopic(topic: string): LearnTopic | null {
  return topics[topic.toLowerCase()] ?? null;
}
