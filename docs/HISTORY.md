# Local scan history integrity

Scan history is stored in the project's private `.toolip/history.json` file.
Legacy entries are unsigned and remain local-only convenience data; their
fingerprints or timestamps are not an authenticated timeline. `history diff`
therefore reports every finding as unknown until history is protected.

## Enable authentication

Generate a random 256-bit key outside the repository, restrict it to the owner,
and keep a backup in your approved secret store:

```sh
umask 077
openssl rand -hex 32 > "$HOME/.toolip-history.key"
chmod 600 "$HOME/.toolip-history.key"

toolip history protect --path . --integrity-key "$HOME/.toolip-history.key"
toolip scan --path . --history-integrity-key "$HOME/.toolip-history.key"
toolip history diff --path . --integrity-key "$HOME/.toolip-history.key"
```

The file must contain exactly 64 hexadecimal characters, optionally followed
by a newline. Toolip reads it without following symlinks, requires a regular
owner-only file on POSIX, caps its size, checks file identity and metadata
around the read, and never prints the key. A non-secret key identifier is
derived from the key bytes. Without the key, a protected history cannot be
read or appended to. If an ordinary scan cannot authenticate existing history,
Toolip leaves it intact and warns that it could not update history.

## Rotation and limits

Rotate keys only after backing up both keys and verifying the old chain:

```sh
toolip history rotate-key \
  --path . \
  --current-key "$HOME/.toolip-history.key" \
  --new-key "$HOME/.toolip-history-next.key"
```

The rotation verifies every retained entry under the old key, then writes a new
chain under the new key as one atomic local-state transaction. HMAC-SHA-256
records bind the complete entry, sequence, key ID and preceding record. The
head digest detects truncation when the stored head is retained; the chain
detects edits, interior deletion, reordering and replay. `history clear` also
requires the current key to read a protected store and can preserve an empty
authenticated store when passed `--integrity-key`.

The design provides tamper evidence against edits made without access to the
key; it cannot prevent a user or attacker with the key from rewriting history,
restore an earlier valid whole-file snapshot, or prove the machine itself is
uncompromised. Detecting whole-store rollback requires a monotonic checkpoint
outside the writable history store, which this local-only format does not
provide. A key loss makes authenticated history unverifiable. Protect the key
separately from the repository and rotate it with both old and new key files
available. Computing one new HMAC costs
O(Bₑ), where Bₑ is the serialized new entry. The complete append transaction
is O(Bₕ + Eₕ) because it validates and atomically rewrites the bounded history
of Bₕ bytes and Eₕ entries. Reads and key rotation are also O(Bₕ + Eₕ), with
O(Bₕ + Eₕ) peak additional space for the parsed store, canonical record input,
and atomic replacement buffer; the limits are 32 MiB and 5,000 entries.
