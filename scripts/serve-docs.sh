#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-8000}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLIC_DIR="$ROOT/public"
RELAY_DOC_TARGET="${TMPDIR:-/tmp}/pigeon-relay-docs"
CORE_DOC_TARGET="${TMPDIR:-/tmp}/pigeon-core-docs"
DOCC_HOSTING_BASE_PATH="${DOCC_HOSTING_BASE_PATH:-api}"

cd "$ROOT"

echo "Building MkDocs..."
uv run --group docs mkdocs build --strict

echo "Building pigeon-core rustdoc..."
rm -rf "$CORE_DOC_TARGET" "$PUBLIC_DIR/api/pigeon-core"
cargo doc \
  --manifest-path pigeon-core/Cargo.toml \
  --no-deps \
  --document-private-items \
  --target-dir "$CORE_DOC_TARGET"
mkdir -p "$PUBLIC_DIR/api/pigeon-core"
cp -R "$CORE_DOC_TARGET/doc" "$PUBLIC_DIR/api/pigeon-core/doc"

echo "Building PigeonMesh DocC..."
mkdir -p "$PUBLIC_DIR/api/PigeonMesh"
swift package \
  --package-path PigeonMesh \
  --allow-writing-to-directory "$PUBLIC_DIR/api/PigeonMesh" \
  generate-documentation \
  --target PigeonMesh \
  --output-path "$PUBLIC_DIR/api/PigeonMesh" \
  --transform-for-static-hosting \
  --hosting-base-path "$DOCC_HOSTING_BASE_PATH/PigeonMesh"

echo "Building pigeon-relay rustdoc..."
rm -rf "$RELAY_DOC_TARGET" "$PUBLIC_DIR/api/pigeon-relay"
cargo doc \
  --manifest-path pigeon-relay/Cargo.toml \
  --no-deps \
  --document-private-items \
  --target-dir "$RELAY_DOC_TARGET"
mkdir -p "$PUBLIC_DIR/api/pigeon-relay"
cp -R "$RELAY_DOC_TARGET/doc" "$PUBLIC_DIR/api/pigeon-relay/doc"

cat <<EOF

Docs are ready:
  http://localhost:$PORT/

API docs:
  http://localhost:$PORT/api/pigeon-core/doc/pigeon_core/
  http://localhost:$PORT/api/PigeonMesh/documentation/pigeonmesh/
  http://localhost:$PORT/api/pigeon-relay/doc/pigeon_relay/

Press Ctrl-C to stop the server.
EOF

cd "$PUBLIC_DIR"
uv run -m http.server "$PORT"
