# Offline advisory snapshots

Toolip can keep OSV, EPSS and CISA KEV responses in a bounded local snapshot.
The snapshot is replaced atomically, protected by a process lock and checked
against a canonical SHA-256 digest. That digest detects corruption; it does not
establish who produced the data. Signed snapshots use Ed25519 and bind the
signature to the full snapshot payload and key identifier.

Create a private key with owner-only permissions and export its public key:

```sh
openssl genpkey -algorithm ED25519 -out toolip-intelligence-private.pem
chmod 600 toolip-intelligence-private.pem
openssl pkey -in toolip-intelligence-private.pem -pubout -out toolip-intelligence-public.pem
```

Refresh the snapshot from the resolved dependency graph:

```sh
toolip intelligence snapshot refresh \
  --path . \
  --file .toolip/advisories.json \
  --signing-key toolip-intelligence-private.pem \
  --signing-key-id team-intelligence-2026
```

Use it without network requests only after verifying it with the trusted public
key:

```sh
toolip scan \
  --path . \
  --offline \
  --data-snapshot .toolip/advisories.json \
  --snapshot-public-key toolip-intelligence-public.pem
```

`--snapshot-public-key` requires a signed snapshot and verifies its Ed25519
signature before any cached record can affect vulnerability findings. A
snapshot opened without a trusted key reports its signature as unverified;
unverified persistent records are not used as advisory results. In offline mode
that leaves the relevant analysis incomplete. Refreshing a signed snapshot
requires the matching signing key. Signing with a new key does not carry forward
records from an unsigned or unverified snapshot.

`toolip intelligence snapshot verify --file ... --public-key ...` checks both
the digest and signature. Without `--public-key`, the command reports digest
integrity and the signature state separately. `--max-advisory-age-days` marks
old OSV records and EPSS/KEV feeds stale; stale or missing records remain
unknown and cannot support an all-clear result. The default storage is local to
the path supplied by the user; Toolip does not publish snapshots or keys.

Snapshot refresh uses the selected lockfile graph, bounded provider responses,
timeouts and retries. Unsupported ecosystems and unresolved package instances
remain incomplete. Snapshot contents are capped at 64 MiB and 200,000 records.
