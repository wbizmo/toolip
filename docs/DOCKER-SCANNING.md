# Dockerfile Security

Run:

```bash
toolip docker-scan
toolip docker-scan --path ./service --json
```

`--path` selects the project root and `--json` writes the analyzer summary,
coverage, warnings and redacted findings. Partial or failed Dockerfile coverage
is reported in both output forms and uses the shared incomplete-analysis exit
status by default; `--no-fail-on-incomplete` keeps the result visible while
allowing scripts to continue.

The analyzer reads bounded Dockerfile text as data; it never runs a build. It
checks for root execution, secret-like `ARG`/`ENV` values, unpinned external
images, remote `ADD`, unsafe remote-download shell pipelines, and package
installation without same-layer cleanup. Findings redact matched instruction
text. Empty secret-named `ARG`s and BuildKit secret mounts are not treated as
literal embedded secrets.

Named and numeric `FROM` references build an indexed stage graph. A stage that
uses an earlier stage inherits its known `USER` and `HEALTHCHECK` state, and
later instructions override that state. `scratch` starts as UID 0 with no
health check. An external image's user and health-check metadata cannot be
verified offline; absent explicit settings produce low-confidence candidates
and partial coverage. A username such as `app` does not prove its UID, so the
analyzer also reports that identity as unknown. `ONBUILD` effects, unresolved
build arguments, invalid stage references, unsupported instructions, and
incomplete continuations/heredocs keep coverage partial.

The bounded `COPY --from` model distinguishes earlier named/numeric stages
from external image sources. External images without a 64-digit SHA-256 digest
produce `TLP-DOCKER-008`; properly pinned external images do not.
Invalid, future or ambiguous stage references, variables and unknown image
grammar are reported as **incomplete**, not verified. Remote image metadata
is never downloaded or trusted. A global `ARG` default, even one
containing an image digest, can be overridden by the build caller; a
`FROM` depending on it cannot establish an immutable image pin.
The visible default can still support a low-confidence unpinned-image finding,
without claiming the actual build used that value.

The bounded parser joins line continuations and recognizes supported Docker
heredocs, JSON-form `ADD`, and `FROM --platform` forms. It is not a complete
Dockerfile frontend, image metadata resolver, or Docker build validator. Global
`ARG` expansion handles the `-`, `:-`, `+`, and `:+` fallback modifiers and
respects the active Docker escape directive; escaped variable references stay
unresolved and keep coverage partial. Other shell-style parameter modifiers
remain unsupported and are reported as unknown. Modifier behavior follows the
[Dockerfile environment replacement reference](https://docs.docker.com/reference/dockerfile/#environment-replacement).
The standard `docker/dockerfile:1` frontend family is recognized; custom,
invalid and duplicate `# syntax` directives make instruction semantics
incomplete. Toolip never pulls or executes a frontend image.

## Input and performance bounds

Dockerfile input uses the shared bounded text reader: at most 20,000 eligible
text files, 2 MiB per file and 64 MiB total per analyzer run. ARG substitutions
share an 8 MiB cumulative expanded-output budget per Dockerfile; when it is
exceeded, affected image metadata remains unknown. Parsing and expansion take
O(B + X) time and O(B + X) additional space for B input bytes and X expanded
bytes, with X capped at 8 MiB. A file that exceeds the reader budget, expansion
budget, changes during reading, or is cancelled is reported as incomplete
rather than treated as a clean scan. The command and analyzer API keep their
existing names and result shape; JSON consumers should use the shared
`analysis` coverage state to distinguish complete, partial and failed results.
