# Toolip Vault

Toolip Vault is local encrypted storage for development secrets. Vault operations are designed so storage, persistence, and export preserve the same security boundary as the encryption layer.

## Storage format

The current vault file format is **version 1**.

A version-1 vault stores AES-256-GCM ciphertext plus a random salt, IV, and authentication tag. The master password is converted to the encryption key with `scrypt` and is never stored in the vault file.

Existing valid version-1 vaults remain readable after upgrades. Unsupported future/unknown versions fail closed with `VAULT_UNSUPPORTED_VERSION`; malformed JSON, invalid schema, invalid base64, and invalid decrypted payloads are reported as controlled Toolip errors rather than being treated as an empty vault.

## Persistence guarantees

Mutations use an atomic directory lease from `proper-lockfile` with a 30-second stale threshold and 10-second heartbeat. The owner token is stored next to the lock and checked before each atomic replacement; release is skipped if that token or lease changes. Stale recovery uses lease timestamps, not process IDs, so PID reuse does not strand a vault. Lock acquisition times out after five seconds with `VAULT_LOCK_TIMEOUT`; permission and compromised-lease errors fail closed.

Encrypted updates are written through an exclusively created, uniquely named temporary file in the same directory, flushed, checked against the current lock owner and validated parent directory, then atomically renamed over the primary vault. The containing directory is synced where supported. A failed or interrupted temporary write therefore leaves either the previous complete vault or the newly committed complete vault.

The final vault directory must be a real, current-user-owned directory; POSIX permissions are repaired through an open directory handle to `0700`. The vault must be a regular, current-user-owned file and is opened without following its final symlink; permissions are repaired through that open file handle to `0600`. A symlinked ancestor is treated only as a path alias: the final `.toolip` directory is secured and its identity is revalidated before commit, so replacing that parent after validation fails closed. Toolip rejects a symlinked vault, symlinked final state directory, foreign-owned POSIX path, and path replacement detected during the operation.

On Windows, the Node filesystem API does not expose a portable owner/DACL verifier or POSIX mode boundary. Toolip rejects detected symlinks/reparse points and compares opened-file identity, uses the same atomic directory lease, and relies on the user's inherited Windows ACL for confidentiality. It does not claim to repair or verify a Windows DACL. The threat model is a local user able to race an unsafe state path; it does not treat another process running as the same user as an isolation boundary.

## Export formats

`toolip vault export` requires an explicit, well-defined representation:

```bash
toolip vault export --format shell
toolip vault export --format json
```

### Shell

Shell export is intended for POSIX-compatible shells. Values use single-quote escaping so characters such as `$`, `$()`, backticks, double quotes, backslashes, spaces, and newlines remain literal when the generated assignments are sourced.

Shell export only accepts keys that are valid environment-variable identifiers (`[A-Za-z_][A-Za-z0-9_]*`). This restriction is applied at the **shell export boundary**, not when secrets are stored, so older vaults and JSON export can continue to represent other key names.

### JSON

JSON export serializes secret names and values using JSON string encoding. It performs no shell interpolation and can represent keys that are not valid shell environment-variable names.

## Compatibility

The encrypted vault file remains versioned independently from export formatting. Changes to export quoting do not require rewriting existing encrypted data. If the encrypted file format changes in a future Toolip release, migration behavior must be explicit and older supported versions must never be silently reinterpreted as a different format.
