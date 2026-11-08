# AST Security Analysis

Toolip uses the TypeScript Compiler API to understand JavaScript and TypeScript syntax before reporting dangerous-code findings.

## Command

```bash
toolip ast-scan
```

## Supported Source Files

- JavaScript
- JSX
- TypeScript
- TSX
- ESM `.mjs`
- CommonJS `.cjs`

Declaration files, source maps, and compiled `dist` output are excluded.

## Current Rules

- `TLP-AST-001`: direct `eval()` execution
- `TLP-AST-002`: dynamic `Function` construction
- `TLP-AST-003`: resolved `child_process.exec()` execution
- `TLP-AST-004`: resolved `child_process.execSync()` execution
- `TLP-AST-005`: request-derived input reaches common SQL query sinks
- `TLP-AST-006`: request-derived input reaches common outbound URL sinks
- `TLP-AST-007`: request-derived input reaches HTML-writing sinks
- `TLP-AST-008`: request-derived keys or objects reach prototype mutation sinks
- `TLP-AST-009`: request-derived input reaches imported Node.js filesystem APIs
- `TLP-AST-010`: request-derived input reaches `exec`/`execSync` or a child-process API explicitly configured with `shell: true`
- `TLP-AST-011`: request-derived input reaches a dynamically selected child-process method whose shell behavior cannot be resolved
- `TLP-AST-012`: request-derived input reaches the known unsafe `node-serialize` `unserialize()` API
- `TLP-RACE-001`: same-path filesystem check followed by a later path operation
- `TLP-RACE-002`: object read/check/write without an evident atomic predicate
- `TLP-RACE-003`: unbounded `Promise.all(collection.map(...))` with side effects
- `TLP-AUTH-001`: low-confidence BOLA candidate for a request-controlled object lookup in a recognized route handler with no visible owner, tenant, permission, or role check
- `TLP-DATA-001`: credential-like `process.env` values flow through aliases, object spreads, async callbacks, and resolved project helper calls to selected logging, telemetry, response, outbound-request, and storage sinks

Toolip resolves named imports, aliased imports, namespace imports, CommonJS destructuring, and common `require(...).exec` assignments with lexical binding scopes. The AST analyzer builds TypeScript symbol graphs from the exact bounded source strings in the immutable scanner snapshot. For files that are external modules without ambient declarations, it processes one weakly connected local-import component at a time, preserving imported helper and re-export flows while bounding checker memory by the largest component. Script files, declaration files, ambient modules, and global augmentations retain a project-wide symbol environment because they can affect files without import edges. The compiler host is denied access to repository paths outside that snapshot and to installed package source; only TypeScript's own standard library files are available outside it. The complete input snapshot is capped at 50,000 files and 64 MiB; each component is subject to the same file/byte limits and an 8,000,000 flow-work-unit budget. A component that exceeds those bounds fails the project analysis and marks AST coverage incomplete rather than clean. Direct single-file analysis has a 250,000-work-unit limit, and budget failures make AST coverage incomplete rather than clean.

The request source/sink rules recognize a bounded local set of request inputs (`req`/`request`/`ctx` query, parameter, and body properties) and sinks such as `query`/`execute`/`raw`, `fetch`/common HTTP clients, imported `node:fs`/`fs/promises` read/write APIs, `innerHTML`/`document.write`, computed object keys, `Object.assign`/`Object.setPrototypeOf`, and the specifically known unsafe `node-serialize` `unserialize()` API. Shell-command findings distinguish `exec`/`execSync` and explicit `shell: true` options from default argument-array `execFile`/`spawn`; computed child-process methods produce a low-confidence review lead. Generic `JSON.parse()` is not treated as unsafe deserialization. The analyzer does not prove whether a separate canonical-containment guard is sound or model every shell option assembled through dynamic spreads. Findings use medium confidence and are review leads, not proof of exploitability or a complete taint analysis.

For the captured AST snapshot, local import edges are collected by one syntax-tree walk over `S` nodes, then resolved against the immutable file set. Strongly connected components are hashed in deterministic order; sorting roots, component members, and dependency digests gives worst-case `O(S + V log V + E log E)` time and `O(S + V + E)` additional space for this digest pass, where `V` is the number of captured source files and `E` is the resolved local import-edge count. The existing TypeScript parser/checker and taint passes have separate byte, file, and work-unit limits. A changed file invalidates its SCC and transitive importers; unrelated files retain their cache keys. Unresolved or dynamic imports are not edges and remain a limitation of the heuristic analysis.

The authorization candidate pass reuses the same parsed source tree. It recognizes direct Express-style route callbacks, Nest-style HTTP method decorators with `@Param`, `@Query`, and `@Body` values, selected authorization decorators, and exported Next.js method handlers. It looks for common ORM lookup methods that receive request parameters, including values copied through same-handler local aliases or destructured from request containers, and suppresses candidates when it sees direct owner/tenant predicates, injected current-user/current-tenant scopes, explicit assertion-style calls, route-level role middleware, or resource-specific boolean access checks whose denied branch exits before the lookup. Those checks must receive both an authenticated identity and a request-controlled object identifier; an authentication-only check does not establish object ownership. Awaited guards and common custom names such as `canReadWorkspaceDocument` are recognized. The pass still does not resolve the helper implementation, cross-file middleware semantics, policy engines, database views, shared-resource rules, or framework-specific authorization semantics. A candidate is therefore low confidence and must be reviewed against the actual access-control model. No candidate is not evidence that a route is authorized.

Within one route handler, the pass also follows unique, non-reassigned authenticated identity and tenant aliases into nested or shorthand query predicates. If an alias is shadowed or reassigned, it remains unresolved and cannot suppress a candidate. This is a local lexical heuristic; it does not establish the meaning of aliases across modules, closure boundaries, policy helpers, or database query abstractions.

Concurrency rules are same-file heuristics. The analyzer recognizes check-then-use paths, database-style read/check/write sequences without visible version/atomic updates, and `Promise.all` over an unbounded `.map()` callback that contains selected side-effecting calls. A static `.slice(0, N)` bound and known concurrency helper names suppress the fan-out candidate. It does not prove collection size, operation independence, transaction isolation, external lock scope, or runtime scheduling; review each low-confidence finding.

The sensitive-data pass recognizes credential-like `process.env` values and common sensitive property names such as tokens, passwords, email addresses, phone numbers, and government identifiers. It follows local aliases, object construction/spread, async flows, resolved project helper calls, and selected output sinks. Storage sink recognition is limited to imported filesystem write APIs, browser `localStorage`/`sessionStorage`, IndexedDB object stores, and database write methods whose receiver chain contains a recognized database/repository name; these storage candidates are medium severity and low confidence because application-specific data classification is unavailable. It omits source expressions and field names from evidence. Calls named `redact`, `redactSensitive`, `maskSecret`, `maskToken`, `sanitizeSecret`, and `safeSerialize` are treated as sanitizers. Property-name classification is heuristic and may flag intentionally public fields; it does not trace database schemas or user-defined classifications, code outside the captured project, dynamic module resolution, arbitrary serializers, or application-specific sanitizer contracts. Verify every reported flow and sanitizer in context.

## Why AST Analysis

Raw string matching cannot distinguish regular-expression parsing from shell execution. AST analysis keeps those operations separate and avoids the false positive previously found in Toolip v1.

## Limits

AST resolution is static and bounded to symbols resolved from the captured project snapshot. Dynamic module loading, runtime mutation, generated code, sanitizer semantics, framework-specific injection, indirect values, external package implementation details, and imports that cannot be resolved from the snapshot can be missed. Parameter and return propagation is conservative and may report transformed values that are safe in context. SQL drivers and outbound HTTP clients vary; a call named `query` or `fetch` is only a heuristic sink. Browser `fetch` is not server-side request forgery, and findings need application-context review.

Toolip does not prove that an application is free of BOLA/IDOR or authorization defects. Those checks depend on the application's ownership model. For each read, update, and delete endpoint, test a matrix of resource owner, another authenticated user, unauthenticated caller, tenant boundary, and privileged role; assert that every unauthorized request is denied and does not disclose or mutate the resource. Add runtime integration tests for nested resources and identifier substitution, and review authorization at the data-access boundary.

The analyzer reports the files it parsed and its heuristic model in result metadata. A run with no findings means only that these supported patterns were not found in the analyzed input; it is not a clean bill of health.
