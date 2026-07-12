# Contributing to Toolip

Toolip welcomes focused bug fixes, security-rule improvements, tests, documentation corrections, provider integrations, and performance improvements.

## Development Setup

```bash
npm ci
npm run verify
```

## Engineering Expectations

- Keep analyzers independent from CLI output.
- Return normalized findings through shared contracts.
- Use stable rule IDs.
- Redact sensitive evidence.
- Add regression coverage for every bug fix.
- Add integration coverage for command behavior.
- Avoid unbounded concurrency.
- Keep remote operations opt-in.
- Do not weaken release verification.

## Pull Requests

A pull request should explain:

- the problem being solved
- the chosen design
- important tradeoffs
- tests added
- user-visible behavior
- security or compatibility implications

All CI jobs must pass before merge.
