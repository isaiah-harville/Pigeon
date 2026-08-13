#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

before_revision="${1:-}"
current_version="$(tr -d '[:space:]' < site/VERSION)"
publish_version=false

if [[ -z "$before_revision" || "$before_revision" =~ ^0+$ ]]; then
  publish_version=true
else
  previous_version="$(git show "$before_revision:site/VERSION" 2>/dev/null | tr -d '[:space:]' || true)"
  [[ "$previous_version" != "$current_version" ]] && publish_version=true
fi

printf 'version=%s\npublish_version=%s\n' "$current_version" "$publish_version"
