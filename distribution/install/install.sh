#!/bin/sh
# Toolip standalone installer candidate — DO NOT pipe unreviewed remote code
# to a shell. Execute this local, inspectable script only after an approved
# release exists. No installation is performed without an independently
# obtained Ed25519 public key and an exact expected release commit.
set -eu

usage() {
  printf '%s\n' "Usage: install.sh --version X.Y.Z --git-sha 40_HEX --public-key TRUSTED_PEM [--prefix USER_DIRECTORY] [--dry-run]" >&2
  exit 2
}
VERSION=''
GIT_SHA=''
TRUST_KEY=''
PREFIX="${HOME}/.local/bin"
DRY_RUN=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) [ "$#" -ge 2 ] || usage; VERSION=$2; shift 2 ;;
    --git-sha) [ "$#" -ge 2 ] || usage; GIT_SHA=$2; shift 2 ;;
    --public-key) [ "$#" -ge 2 ] || usage; TRUST_KEY=$2; shift 2 ;;
    --prefix) [ "$#" -ge 2 ] || usage; PREFIX=$2; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    *) usage ;;
  esac
done

case "$VERSION" in
  ''|*[!0-9.]*|.*|*.) usage ;;
esac
if ! printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then usage; fi
if ! printf '%s\n' "$GIT_SHA" | grep -Eq '^[a-f0-9]{40}$'; then usage; fi
[ -r "$TRUST_KEY" ] && [ -f "$TRUST_KEY" ] || usage
[ -n "$PREFIX" ] || usage
case "$PREFIX" in
  /*) ;;
  *) printf 'Install prefix must be an absolute directory.\n' >&2; exit 2 ;;
esac

system=$(uname -s)
machine=$(uname -m)
case "$machine" in
  x86_64|amd64) ARCH=x64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) printf 'Unsupported Toolip architecture.\n' >&2; exit 2 ;;
esac
case "$system" in
  Darwin) TARGET="darwin-$ARCH" ;;
  Linux)
    # Only GNU libc is currently described by the candidate release schema.
    # Do not silently install glibc archives on musl systems.
    if ! command -v getconf >/dev/null 2>&1 ||
      ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
      printf 'Unsupported or unverified Linux libc; no installation.\n' >&2
      exit 2
    fi
    TARGET="linux-$ARCH-gnu"
    ;;
  *) printf 'Unsupported Toolip operating system.\n' >&2; exit 2 ;;
esac

ASSET="toolip-$VERSION-$TARGET.tar.gz"
BASE="https://github.com/wbizmo/toolip/releases/download/v$VERSION"
if [ "$DRY_RUN" = true ]; then
  printf 'Review-only. No network or filesystem changes.\n'
  printf 'Release commit: %s\nTarget: %s\nManifest: %s/release-manifest.json\nAsset: %s/%s\n' \
    "$GIT_SHA" "$TARGET" "$BASE" "$BASE" "$ASSET"
  exit 0
fi

for program in curl jq openssl tar mktemp chmod ln cp; do
  command -v "$program" >/dev/null 2>&1 || {
    printf 'Required verification tool unavailable: %s\n' "$program" >&2
    exit 2
  }
done
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD=shasum
else
  printf 'No SHA-256 verification tool available.\n' >&2
  exit 2
fi

# Restrict installation to the user's home instead of allowing a
# root/system-owned target or an unexpected absolute path.
case "$PREFIX" in
  "$HOME"/*) ;;
  *) printf 'Install prefix must be inside HOME.\n' >&2; exit 2 ;;
esac
case "$PREFIX" in
  */../*|*/./*|*/..|*/.)
    printf 'Install prefix must not contain traversal segments.\n' >&2; exit 2 ;;
esac
umask 077
TMP=$(mktemp -d "${TMPDIR:-/tmp}/toolip-install.XXXXXXXX")
STAGING=''
cleanup() {
  if [ -n "$STAGING" ]; then rm -rf -- "$STAGING"; fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM
download() {
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 120 --retry 2 \
    --output "$2" "$1"
}
download "$BASE/release-manifest.json" "$TMP/manifest.json"
download "$BASE/release-manifest.sig" "$TMP/manifest.sig"
# Signature is over the exact original JSON bytes; the PEM trust anchor was
# supplied out of band and MUST NOT be downloaded beside this manifest.
openssl base64 -d -A -in "$TMP/manifest.sig" -out "$TMP/signature.bin"
openssl pkeyutl -verify -rawin -pubin -inkey "$TRUST_KEY" \
  -sigfile "$TMP/signature.bin" -in "$TMP/manifest.json" >/dev/null
jq -e --arg v "$VERSION" --arg s "$GIT_SHA" '
  .schema == "toolip.dev/distribution/v1" and
  .repository == "wbizmo/toolip" and
  .artifactKind == "standalone-runtime-bundle" and
  .version == $v and
  .sourceGitSha == $s and
  (.assets | type == "array" and length > 0 and length <= 32)
' "$TMP/manifest.json" >/dev/null

COUNT=$(jq -r --arg target "$TARGET" '
  [.assets[] | select(.target == $target)] | length
' "$TMP/manifest.json")
[ "$COUNT" = 1 ] || { printf 'Expected target is not uniquely signed.\n' >&2; exit 1; }
EXPECTED_NAME=$(jq -r --arg target "$TARGET" '.assets[] | select(.target == $target) | .filename' "$TMP/manifest.json")
EXPECTED_SHA=$(jq -r --arg target "$TARGET" '.assets[] | select(.target == $target) | .sha256' "$TMP/manifest.json")
EXPECTED_BYTES=$(jq -r --arg target "$TARGET" '.assets[] | select(.target == $target) | .size' "$TMP/manifest.json")
[ "$EXPECTED_NAME" = "$ASSET" ] || { printf 'Signed filename mismatch.\n' >&2; exit 1; }
printf '%s\n' "$EXPECTED_SHA" | grep -Eq '^[a-f0-9]{64}$' || exit 1
printf '%s\n' "$EXPECTED_BYTES" | grep -Eq '^[1-9][0-9]{0,9}$' || exit 1

download "$BASE/$ASSET" "$TMP/$ASSET"
ACTUAL_BYTES=$(wc -c < "$TMP/$ASSET" | tr -d ' ')
[ "$ACTUAL_BYTES" = "$EXPECTED_BYTES" ] || { printf 'Artifact size mismatch.\n' >&2; exit 1; }
if [ "$HASH_CMD" = sha256sum ]; then
  ACTUAL_SHA=$(sha256sum "$TMP/$ASSET" | cut -d ' ' -f 1)
else
  ACTUAL_SHA=$(shasum -a 256 "$TMP/$ASSET" | cut -d ' ' -f 1)
fi
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || { printf 'Signed checksum mismatch.\n' >&2; exit 1; }

# Only one regular root entry named toolip is permitted. Never extract an
# arbitrary archive tree into the user's home directory.
ARCHIVE_LIST=$(tar -tzf "$TMP/$ASSET")
[ "$ARCHIVE_LIST" = toolip ] || { printf 'Unexpected release archive layout.\n' >&2; exit 1; }
mkdir -m 700 "$TMP/extracted"
tar -xzf "$TMP/$ASSET" -C "$TMP/extracted" toolip
[ -f "$TMP/extracted/toolip" ] && [ ! -L "$TMP/extracted/toolip" ] || {
  printf 'Archive executable is not a regular file.\n' >&2; exit 1
}
chmod 700 "$TMP/extracted/toolip"

# Refuse existing symlinked destination or an existing binary overwrite.
[ ! -L "$PREFIX" ] || { printf 'Install prefix is a symlink.\n' >&2; exit 1; }
if [ ! -d "$PREFIX" ]; then mkdir -p -m 700 "$PREFIX"; fi
[ -d "$PREFIX" ] && [ ! -L "$PREFIX" ] || exit 1
[ ! -e "$PREFIX/toolip" ] && [ ! -L "$PREFIX/toolip" ] || {
  printf 'Toolip already exists at the installation target.\n' >&2; exit 1
}
# Stage on the destination filesystem; a hard-link create is atomic and
# refuses an existing destination, unlike mv -n which can silently succeed
# without writing after a race. Never overwrite a pre-existing executable.
STAGING=$(mktemp -d "$PREFIX/.toolip-stage.XXXXXXXX")
cp "$TMP/extracted/toolip" "$STAGING/toolip"
chmod 700 "$STAGING/toolip"
ln "$STAGING/toolip" "$PREFIX/toolip"
[ -f "$PREFIX/toolip" ] && [ ! -L "$PREFIX/toolip" ] || {
  printf 'Installation did not complete.\n' >&2; exit 1
}
printf 'Installed signed Toolip candidate version %s to %s/toolip\n' "$VERSION" "$PREFIX"
printf 'Review PATH configuration manually; nothing was added to shell profiles.\n'
