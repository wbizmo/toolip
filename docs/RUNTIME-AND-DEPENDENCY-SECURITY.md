# Runtime and Dependency Security

The Node.js executable is part of Toolip's security boundary. A green `npm audit` cannot patch a vulnerable Node.js binary, and `package.json#engines` alone does not stop an install (npm treats it as a warning unless `engine-strict` is set). Toolip therefore enforces its runtime floor in three places: the CLI itself, CI, and the packed artifact.

## Supported runtimes

| Line       | Minimum (patch floor) | Recommended |
| ---------- | --------------------- | ----------- |
| Node.js 22 | **22.23.4**           | 22.23.4+    |
| Node.js 24 | **24.22.1**           | 24.22.2+    |

Floors come from the [October 2026 Node.js security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) and the [24.22.2 follow-up](https://nodejs.org/en/blog/release/v24.22.2), verified on 2026-11-04. Node 23, 25 and 26 are not supported. The reviewed source of truth is [`security/runtime-floors.json`](../security/runtime-floors.json); `package.json#engines.node` (`^22.23.4 || >=24.22.1 <25`), `src/core/runtime-check.ts`, `scripts/verify-node.mjs` and tests must agree. Re-check upstream advisories before every release and whenever Node.js publishes a security release.

## Behavior on an unpatched or unsupported runtime

- **Scanning and all other commands fail closed**: Toolip prints the reason and exits with code 1 before running any analysis.
- `--version`, `--help` and `self-test` still run so users can read the message; `self-test` reports a failed "Supported patched Node.js" check and exits non-zero.
- `TOOLIP_ALLOW_UNPATCHED_NODE=1` is an explicit, logged operator override: Toolip runs and prints a warning each time. It is intended for short, supervised transitions, not CI.

## CI and release

`scripts/verify-node.mjs` is dependency-free (it runs before `npm ci`) and fails the Node 22/24 × Linux/macOS/Windows matrix, the static job and release checks when the resolved `process.versions.node` is below the floor, when `engines.node` admits an unpatched version (e.g. 22.23.3, 24.22.0) or any unsupported major. Tests cover the negative and positive fixtures (`22.23.3`, `24.22.0`, `22.23.4`, `24.22.1`, `24.22.2`, Node 23/25/26). CI uses `check-latest` so matrix cells run the newest patch release.

Containers, deployment images and standalone runtimes must be rebuilt with a patched Node.js image; Toolip cannot verify those from the package.

## Reachability review of the October 2026 Node.js advisories

This is an applicability review, not a claim of a proven Toolip exploit.

| Advisory                                        | Toolip use                                                                                                                                                                                                    | Assessment                                                                                            |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| CVE-2026-111497 Brotli decoder out-of-bounds    | No direct `node:zlib` use in `src/`. HTTPS responses from the npm registry (`fetch` in dependency-confusion analysis, `pacote`/`npm-registry-fetch` in package-health) may be content-decoded by the runtime. | Inherited runtime exposure via registry responses; mitigated only by patching Node.js.                |
| CVE-2026-105482 `dns.resolve*` NUL truncation   | No direct `node:dns` use. Hostnames are the fixed `registry.npmjs.org` or the user's configured registry.                                                                                                     | Not reachable through attacker-controlled hostnames in Toolip code; registry config is user-supplied. |
| CVE-2026-106069 / CVE-2026-105483 TLS IP checks | Requests target a DNS hostname, not IP literals, unless the user configures an IP-based registry.                                                                                                             | Low applicability; inherited runtime risk for custom registries.                                      |
| Other HTTP/TLS/crypto/permission-model fixes    | Toolip uses `node:crypto` for the vault and HTTP(S) through `fetch`/`pacote`; it does not use the permission model, SEA or snapshots.                                                                         | Fixed by patching Node.js.                                                                            |

No confirmed Toolip-specific exposure was found requiring separate escalation.

## Dependency advisory regression gate

`npm audit` (production and development, every severity) and `npm audit signatures` run in CI against the live advisory database. In addition, [`security/advisory-floors.json`](../security/advisory-floors.json) records the vulnerable ranges and GHSA identifiers fixed in Batch 00; `scripts/verify-lockfile.mjs` fails if **any** installed copy of those packages (including nested duplicates) falls in a vulnerable range, so a downgrade or a transitive re-introduction cannot go unnoticed even when the advisory feed is unreachable. Never delete an entry to make a build pass.

- **MCP SDK (#50):** `@modelcontextprotocol/sdk` 1.32.2 (all advisories covered by `>=1.32.0`). Toolip uses only the stdio transport (`StdioServerTransport`); HTTP/session/OAuth features of the SDK are not started by any Toolip command, so HTTP-transport advisories are inherited-only. Every tool resolves its `root` through the workspace boundary; `tests/mcp-stdio-smoke.test.ts` drives the real server over stdio, checks boundary denial and malformed input.
- **undici (#51):** the only `undici` copy is 8.12.3, installed beneath `pacote → @npmcli/run-script → node-gyp` (build tooling). Toolip's own `fetch` calls use the undici bundled in Node.js, which is why the Node floor matters. Advisories affecting `undici <6.29.1` are in the regression gate.
- **Version integrity (#52):** `scripts/verify-lockfile.mjs` also requires `package.json`, the lockfile top level and `packages[""]` to carry the same name and version; the packed-artifact check compares the installed CLI `--version` with `package.json`.

## Overrides

`glob` (`^14.0.3`) and `minimatch` (`^11.0.4`) are forced because `pacote` 22's dependencies still declare vulnerable ranges. Remove an override once its parent depends on a patched range.

## Maintenance policy for v2.2.x (#87)

Decision recorded on 2026-11-04: **no v2.2.x release is published as part of the v3.2.1 program.** The published v2.2.1 remains unchanged. The Node.js patch floor and dependency fixes ship in v3.2.1 and are enforced by the CLI at runtime. If the owner later authorizes a compatible v2.2.x security patch, it must:

1. be cut from a protected maintenance branch containing only reviewed backports and the same regression corpus;
2. warn (rather than fail) on unpatched runtimes first, because hard-failing is a behavior change;
3. use a new version, its own `RELEASE_NOTES_v2.2.x.md` and `CHANGELOG.md` entry, and the same manual, protected release workflows.

Until then, users on v2.2.1 should upgrade Node.js to 22.23.4+ / 24.22.1+ (24.22.2+ recommended) and run `npm audit` for their own trees.
