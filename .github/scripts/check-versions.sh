#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

die() {
  echo "error: $*" >&2
  exit 1
}

read_version_file() {
  local path="$1"
  local version
  version="$(tr -d '[:space:]' < "$path")"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] ||
    die "$path must contain a semantic version, found '$version'"
  printf '%s' "$version"
}

crate_version() {
  local manifest="$1"
  local version
  version="$(sed -nE 's/^version = "([^"]+)"$/\1/p' "$manifest" | head -n 1)"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] ||
    die "$manifest must declare a semantic package version, found '$version'"
  printf '%s' "$version"
}

ios_version="$(read_version_file Pigeon/VERSION)"
website_version="$(read_version_file site/VERSION)"
core_version="$(crate_version pigeon-core/Cargo.toml)"
mesh_version="$(crate_version pigeon-mesh/Cargo.toml)"
relay_version="$(crate_version pigeon-relay/Cargo.toml)"

ios_project_version_count="$(grep -c "MARKETING_VERSION = ${ios_version};" Pigeon/Pigeon.xcodeproj/project.pbxproj || true)"
# Debug and Release for the app and for its notification service extension;
# App Store Connect rejects an extension whose version differs from the app's.
[[ "$ios_project_version_count" == "4" ]] ||
  die "Pigeon/VERSION ($ios_version) must match the app and notification extension MARKETING_VERSION values"

[[ $# -eq 0 ]] || die "version validation does not accept release tags"
printf 'iOS %s; website %s; core %s; mesh %s; relay %s\n' \
  "$ios_version" "$website_version" "$core_version" "$mesh_version" "$relay_version"
