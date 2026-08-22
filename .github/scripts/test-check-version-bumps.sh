#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

mkdir -p \
  "$fixture/.github/scripts" \
  "$fixture/Pigeon/Pigeon/Core/Session" \
  "$fixture/site" \
  "$fixture/pigeon-core/src" \
  "$fixture/pigeon-mesh/src" \
  "$fixture/pigeon-relay/src"
cp "$repo_root/.github/scripts/check-version-bumps.sh" "$fixture/.github/scripts/"

printf '1.2.0\n' > "$fixture/Pigeon/VERSION"
printf '0.1.0\n' > "$fixture/site/VERSION"
printf '[package]\nversion = "0.1.0"\n' > "$fixture/pigeon-core/Cargo.toml"
printf '[package]\nversion = "0.1.0"\n' > "$fixture/pigeon-mesh/Cargo.toml"
printf '[package]\nversion = "0.1.0"\n' > "$fixture/pigeon-relay/Cargo.toml"
printf 'baseline\n' > "$fixture/Pigeon/Pigeon/Core/Session/Example.swift"

git -C "$fixture" init -q
git -C "$fixture" config user.email release-test@pigeon.invalid
git -C "$fixture" config user.name "Pigeon release test"
git -C "$fixture" add .
git -C "$fixture" commit -qm baseline

printf 'changed\n' > "$fixture/Pigeon/Pigeon/Core/Session/Example.swift"
if bash "$fixture/.github/scripts/check-version-bumps.sh" HEAD >/dev/null 2>&1; then
  echo "error: nested iOS source change passed without a version bump" >&2
  exit 1
fi
