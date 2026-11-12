# Dockerfile Security

Run:

```bash
toolip docker-scan
```

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

The bounded parser joins line continuations and recognizes supported Docker
heredocs, JSON-form `ADD`, and `FROM --platform` forms. It is not a complete
Dockerfile frontend, image metadata resolver, or Docker build validator.
