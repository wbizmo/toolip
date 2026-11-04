## Scope and linked issues

Closes #
<!-- Use Refs #N for partially addressed issues. Only merged PRs to main close fully resolved issues. -->

## Correctness and security invariants

- Expected behavior and failure/unknown semantics:
- Trust boundaries, authorization, secrets and compatibility:
- Tests for adversarial inputs, regression and concurrent execution:

## Algorithmic analysis (required)

| Hot path / operation | Input dimensions | Previous worst-case time | New worst-case time | Previous peak space | New peak space |
| -------------------- | ---------------- | ------------------------ | ------------------- | ------------------- | -------------- |
|                      |                  |                          |                     |                     |                |

- Data structures and indexing build costs:
- Worst-case and pathological input:
- CPU/memory/concurrency limits and cancellation:
- Benchmarks or why a benchmark is not applicable:

## Verification

- [ ] `npm ci` and `npm run typecheck`
- [ ] `npm run quality` and `npm run build`
- [ ] Tests/regression fixtures and `npm run audit:runtime`
- [ ] PR lint/formatter, secret scan, CodeQL and OS/Node matrix reviewed
- [ ] Docs and issue acceptance criteria updated
- [ ] No npm/GitHub release triggered or publish credentials added
- [ ] Ready for merge into `main`; linked issues close on merge
