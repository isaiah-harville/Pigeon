#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <base-git-revision>" >&2
  exit 2
fi

cd "$(dirname "$0")/../.."
base="$1"
git cat-file -e "$base^{commit}" 2>/dev/null || {
  echo "error: base revision '$base' is unavailable; checkout full history" >&2
  exit 1
}

changed_files="$(git diff --name-only "$base")"
failures=0

version_changed() {
  local file="$1"
  local base_version current_version
  if [[ "$file" == */Cargo.toml ]]; then
    base_version="$(git show "$base:$file" 2>/dev/null | sed -nE 's/^version = "([^"]+)"$/\1/p' | head -n 1)"
    current_version="$(sed -nE 's/^version = "([^"]+)"$/\1/p' "$file" | head -n 1)"
    [[ "$base_version" != "$current_version" ]]
  else
    ! cmp -s <(git show "$base:$file" 2>/dev/null || true) "$file"
  fi
}

ios_version_is_unreleased() {
  local version
  version="$(tr -d '[:space:]' < Pigeon/VERSION)"
  ! git show-ref --verify --quiet "refs/tags/v${version}" &&
    ! git show-ref --verify --quiet "refs/tags/ios-v${version}"
}

require_bump() {
  local component="$1"
  local version_file="$2"
  shift 2
  local file pattern changed=false

  while IFS= read -r file; do
    for pattern in "$@"; do
      if [[ "$file" == $pattern ]]; then
        changed=true
        break 2
      fi
    done
  done <<< "$changed_files"

  if [[ "$changed" == true ]] && ! version_changed "$version_file"; then
    if [[ "$component" == "iOS app" ]] && ios_version_is_unreleased; then
      echo "iOS app remains on unreleased version $(tr -d '[:space:]' < Pigeon/VERSION)."
      return
    fi
    echo "error: $component changed without a version bump in $version_file" >&2
    failures=$((failures + 1))
  fi
}

require_bump "iOS app" Pigeon/VERSION \
  "Pigeon/Pigeon/Core/*" "Pigeon/Pigeon/Features/*" "Pigeon/Pigeon/PigeonApp.swift" \
  "Pigeon/Pigeon/Info.plist" "Pigeon/Pigeon.xcodeproj/*"

require_bump "website" site/VERSION \
  "site/index.html" "site/privacy-policy/*" "site/support/*" "site/styles.css" \
  "site/assets/*" "site/deploy/*"

require_bump "pigeon-core" pigeon-core/Cargo.toml \
  "pigeon-core/src/*" "pigeon-core/tests/*" "pigeon-core/build.rs" \
  "pigeon-core/Cargo.toml" "proto/*"

require_bump "pigeon-mesh" pigeon-mesh/Cargo.toml \
  "pigeon-mesh/src/*" "pigeon-mesh/tests/*" "pigeon-mesh/Cargo.toml"

require_bump "pigeon-relay" pigeon-relay/Cargo.toml \
  "pigeon-relay/src/*" "pigeon-relay/tests/*" "pigeon-relay/build.rs" \
  "pigeon-relay/Dockerfile" "pigeon-relay/Cargo.toml"

if ((failures > 0)); then
  echo "Bump each listed component using semantic versioning." >&2
  exit 1
fi

echo "Every changed component includes a version bump."
