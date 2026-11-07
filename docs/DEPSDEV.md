# deps.dev Package Intelligence

Toolip uses the deps.dev v3 API to inspect exact npm package versions.

## Command

```bash
toolip package-health express 5.0.0
```

The command reports published date, deprecation, SPDX license identifiers, advisory identifiers, dependency graph size, related projects, and provenance/attestation metadata reported by deps.dev. It labels how many records deps.dev marks verified, but **Toolip does not independently verify those signatures, issuer identities, repository identities, or artifact digests in this command**. These provider annotations are evidence to review, not a package trust verdict.

For the repository being checked by the trusted Stage A workflow, the gate
checks each npm tarball against the exact lockfile integrity and runs
`npm audit signatures` over the scanned lock graph before Stage B is approved.
That check is limited to npm's registry-signature mechanism and the exact
reviewed graph; it does not establish that signed package contents are benign
or that an expected source repository produced them. Private scopes are not
sent to public metadata providers without explicit opt-in.

`toolip package-health --path` joins review signals to exact lockfile
instances and includes the sanitized registry origin, tarball URL, integrity
digest, and resolution state in JSON output. Custom registry and private-scope
instances stay `not_queried` by public providers; showing a lock digest is
evidence of the expected artifact identity, not proof that the artifact's
signature or contents are trustworthy.

The default provider keeps up to 2,000 successful metadata responses in a
process-local least-recently-used cache for five minutes. The cache stores only
bounded provider responses, returns structured clones, and never caches errors
or unavailable responses. Applications that construct `DepsDevClient` can set
`cacheTtlMs: 0` to disable caching or choose a shorter TTL and smaller entry
limit. License analysis reports cache hits separately from HTTP request and
retry counts. Strict offline scans do not consult the provider or this cache.
