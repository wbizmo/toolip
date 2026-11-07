# npm package health signals

`toolip package-health <package> <exact-version>` inspects one npm package
version. `toolip package-health --path <project>` joins registry evidence to the
exact package instances in the project's `package-lock.json`, including the
install path when the same name and version occurs more than once. It does not
coerce manifest ranges into installed versions. A project without a supported
lockfile is an error or an unresolved inventory, never a clean package-health
result.

The provider uses the fixed HTTPS npm registry origin, rejects redirects,
bounds packuments to 8 MiB and 10,000 versions, times out requests, retries only
rate limits and server errors, caps batches at 1,000 instances, and uses at
most six concurrent lookups by default. Exact name/version lookups are cached
for six hours in process memory. `--offline` prevents npm and deps.dev lookups;
an empty process-local cache is reported as `not_queried`.

Scoped package names are not sent to public metadata providers unless the user
passes `--allow-public-scope`. This is an explicit disclosure choice. Registry
metadata cannot establish whether a package is private by itself, so callers
must not pass internal names to public providers. A future provider policy
should allow explicit registry mappings for private registries; this command
currently queries npmjs.org only.

Signals include release bursts, long periods without a release, new lifecycle
scripts, version-to-version publisher or maintainer identity changes, source
repository changes, and exact-version deprecation. Publisher and maintainer
identities are never included in output; hashes are used only to compare
metadata inside the process. A missing history is reported as unavailable,
not as zero changes. Publisher, maintainer and repository changes have low
confidence because package ownership, automation and release practices can
change for benign reasons. No single signal is a compromise verdict, and the
CLI does not automatically block or suppress a package.

The provider evaluates at most the latest five dated releases when comparing
publisher and maintainer identities, and relies on public packument metadata.
It cannot prove a historical owner transfer, verify an npm provenance
attestation, identify a private registry package, establish maintainer intent,
or detect a compromise that leaves no registry-visible evidence. Treat missing
publisher, maintainer, release or repository history as unknown and confirm
important changes against independently trusted project and registry records.
