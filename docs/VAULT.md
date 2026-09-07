# Toolip Vault

Toolip Vault is local encrypted storage for development secrets. Vault operations are designed so storage, persistence, and export preserve the same security boundary as the encryption layer.

## Storage format

The current vault file format is **version 1**.

A version-1 vault stores AES-256-GCM ciphertext plus a random salt, IV, and authentication tag. The master password is converted to the encryption key with `scrypt` and is never stored in the vault file.

Existing valid version-1 vaults remain readable after upgrades. Unsupported future/unknown versions fail closed with `VAULT_UNSUPPORTED_VERSION`; malformed JSON, invalid schema, invalid base64, and invalid decrypted payloads are reported as controlled Toolip errors rather than being treated as an empty vault.

## Persistence guarantees

Mutating operations are serialized with a vault-local lock file. This prevents concurrent read-modify-write operations from silently overwriting one another.

Encrypted updates are written to a uniquely named temporary file in the same directory and then atomically renamed over the primary vault. A failed or interrupted temporary write therefore does not leave a partially written primary vault file.

On platforms with POSIX permission modes, Toolip creates and repairs the vault file to mode `0600`. The vault directory is created with restrictive permissions as well. Windows does not expose equivalent POSIX mode semantics, so Toolip does not claim that `0600` provides an access-control boundary there.

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
