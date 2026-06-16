#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-8000}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLIC_DIR="$ROOT/public"
RELAY_DOC_TARGET="${TMPDIR:-/tmp}/pigeon-relay-docs"
DOCC_HOSTING_BASE_PATH="${DOCC_HOSTING_BASE_PATH:-api}"

cd "$ROOT"

echo "Building MkDocs..."
uv run --group docs mkdocs build --strict

echo "Building PigeonCrypto DocC..."
mkdir -p "$PUBLIC_DIR/api/PigeonCrypto"
swift package \
  --package-path PigeonCrypto \
  --allow-writing-to-directory "$PUBLIC_DIR/api/PigeonCrypto" \
  generate-documentation \
  --target PigeonCrypto \
  --output-path "$PUBLIC_DIR/api/PigeonCrypto" \
  --transform-for-static-hosting \
  --hosting-base-path "$DOCC_HOSTING_BASE_PATH/PigeonCrypto"

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

echo "Building PigeonRelay rustdoc..."
rm -rf "$RELAY_DOC_TARGET" "$PUBLIC_DIR/api/PigeonRelay"
cargo doc \
  --manifest-path PigeonRelay/Cargo.toml \
  --no-deps \
  --document-private-items \
  --target-dir "$RELAY_DOC_TARGET"
mkdir -p "$PUBLIC_DIR/api/PigeonRelay"
cp -R "$RELAY_DOC_TARGET/doc" "$PUBLIC_DIR/api/PigeonRelay/doc"

cat <<EOF

Docs are ready:
  http://localhost:$PORT/

API docs:
  http://localhost:$PORT/api/PigeonCrypto/documentation/pigeoncrypto/
  http://localhost:$PORT/api/PigeonMesh/documentation/pigeonmesh/
  http://localhost:$PORT/api/PigeonRelay/doc/pigeon_relay/

Press Ctrl-C to stop the server.
EOF

cd "$PUBLIC_DIR"
uv run -m http.server "$PORT"
