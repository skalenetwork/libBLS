#!/usr/bin/env bash
set -euo pipefail

PACKAGE="${1:-}"
VERSION="${2:-}"
TARBALL="${3:-}"

if [[ -z "$PACKAGE" || -z "$VERSION" || -z "$TARBALL" ]]; then
  echo "Usage: $0 <package-name> <version> <tarball-path>" >&2
  exit 2
fi

if [[ ! -f "$TARBALL" ]]; then
  echo "Tarball not found: $TARBALL" >&2
  exit 2
fi

REMOTE_SHASUM="$(npm view "$PACKAGE@$VERSION" dist.shasum 2>/dev/null || true)"
if [[ -z "$REMOTE_SHASUM" ]]; then
  echo "ABSENT: ${PACKAGE}@${VERSION} not found on npm"
  exit 0
fi

LOCAL_SHASUM="$(sha1sum "$TARBALL" | awk '{print $1}')"
if [[ "$LOCAL_SHASUM" == "$REMOTE_SHASUM" ]]; then
  echo "MATCH: ${PACKAGE}@${VERSION} already published and tarball hash matches"
  exit 0
fi

echo "MISMATCH: ${PACKAGE}@${VERSION} exists on npm but the tarball hash does not match" >&2
exit 1
