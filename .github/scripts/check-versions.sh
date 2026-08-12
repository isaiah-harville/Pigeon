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
[[ "$ios_project_version_count" == "2" ]] ||
  die "Pigeon/VERSION ($ios_version) must match both Pigeon app MARKETING_VERSION values"

if [[ $# -eq 0 ]]; then
  printf 'iOS %s; website %s; core %s; mesh %s; relay %s\n' \
    "$ios_version" "$website_version" "$core_version" "$mesh_version" "$relay_version"
  exit 0
fi

tag="$1"
case "$tag" in
  ios-v*) expected="ios-v$ios_version" ;;
  website-v*) expected="website-v$website_version" ;;
  relay-v*) expected="relay-v$relay_version" ;;
  pigeon-core-v*) expected="pigeon-core-v$core_version" ;;
  pigeon-mesh-v*) expected="pigeon-mesh-v$mesh_version" ;;
  *) die "unsupported release tag '$tag'" ;;
esac

[[ "$tag" == "$expected" ]] || die "release tag '$tag' must be '$expected'"
echo "Release tag $tag matches its declared version."
