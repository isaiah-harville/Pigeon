#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

before_revision="${1:-}"
current_version="$(sed -nE 's/^version = "([^"]+)"$/\1/p' pigeon-relay/Cargo.toml | head -n 1)"
publish_version=false

if [[ -z "$before_revision" || "$before_revision" =~ ^0+$ ]]; then
  publish_version=true
else
  previous_version="$(
    git show "$before_revision:pigeon-relay/Cargo.toml" |
      sed -nE 's/^version = "([^"]+)"$/\1/p' |
      head -n 1
  )"
  [[ "$previous_version" != "$current_version" ]] && publish_version=true
fi

printf 'version=%s\npublish_version=%s\n' "$current_version" "$publish_version"
