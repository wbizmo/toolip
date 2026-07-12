#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(pwd)"
PACKAGE_NAME="$(node -p "require('./package.json').name")"
VERSION="$(node -p "require('./package.json').version")"
TARBALL="${PACKAGE_NAME}-${VERSION}.tgz"

rm -f "${PACKAGE_NAME}"-*.tgz

npm ci
npm run verify
npm pack --ignore-scripts

[[ -f "$TARBALL" ]] || {
  echo "Release blocked: expected tarball $TARBALL was not created." >&2
  exit 1
}

node scripts/verify-tarball.mjs "$TARBALL"

printf '\nRelease candidate verified: %s@%s\n' "$PACKAGE_NAME" "$VERSION"
printf 'Artifact: %s/%s\n' "$ROOT" "$TARBALL"
printf 'Do not publish unless this command exits successfully.\n'
