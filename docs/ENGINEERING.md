# Toolip Engineering Standards

## Correctness

Security findings must distinguish confirmed behavior from heuristic indicators. Every finding includes a confidence level. Toolip must not represent static reachability evidence as proof that exploitation is impossible.

## Modularity

Every analyzer implements the common analyzer contract. Shared concerns such as filesystem access, network calls, caching, configuration, and reporting are handled outside analyzers.

## Error Handling

Expected failures use typed errors and stable exit codes. Network providers must distinguish unavailable, rate-limited, unauthorized, malformed, and partial responses.

## Performance

Large repositories must be processed with bounded concurrency. Source files should be parsed once and reused across analyzers. Network responses should be cached by provider, ecosystem, package, version, and response schema.

## Privacy

Toolip remains local-first. Reports redact secrets and local paths by default. Remote publishing and GitHub operations are opt-in and must preview exactly what will leave the machine.

## Testing

Every feature requires:

1. Unit tests for pure logic.
2. Regression tests for previously observed failures.
3. Integration tests for command behavior.
4. Packed-artifact verification when release behavior is affected.

## Releases

A release is not complete when local tests pass. It is complete only after the generated npm tarball is installed in isolation and the packaged CLI successfully runs.
