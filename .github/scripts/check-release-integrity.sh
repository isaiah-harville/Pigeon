#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

fail() {
  echo "error: $*" >&2
  exit 1
}

[[ ! -e pigeon-relay/Cargo.lock ]] || fail "pigeon-relay/Cargo.lock must not shadow Cargo.lock"
grep -q 'COPY Cargo.toml Cargo.lock' pigeon-relay/Dockerfile ||
  fail "relay image must copy the workspace manifest and lockfile"
grep -q 'cargo build --locked --release -p pigeon-relay' pigeon-relay/Dockerfile ||
  fail "relay image must build the locked workspace package"
grep -q 'context: \.' .github/workflows/relay.yml || fail "relay workflow must use root context"
grep -q 'file: pigeon-relay/Dockerfile' .github/workflows/relay.yml ||
  fail "relay workflow must select the relay Dockerfile"

release=.github/workflows/core-release.yml
[[ -f "$release" ]] || fail "core release workflow is missing"
grep -q 'bash pigeon-ffi/build-xcframework.sh' "$release" ||
  fail "core release must build the XCFramework"
grep -q 'shasum -a 256' "$release" || fail "release artifacts must include checksums"
grep -q 'softprops/action-gh-release' "$release" || fail "release artifacts must be published"

echo "Release integrity checks passed."
