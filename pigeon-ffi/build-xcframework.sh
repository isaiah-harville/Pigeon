#!/usr/bin/env bash
#
# Builds PigeonFFIBindings.xcframework from the pigeon-ffi crate and refreshes
# the generated Swift bindings in the sibling PigeonFFI package.
#
# Output:
#   ../Pigeon/PigeonFFI/PigeonFFIBindings.xcframework  (device + simulator static libs)
#   ../Pigeon/PigeonFFI/Sources/PigeonFFI/Generated/   (UniFFI + protobuf Swift)
#   ../Pigeon/PigeonFFI/PigeonFFIBindings.sha256        (tracked output manifest)
#
# Re-run whenever the FFI surface in src/lib.rs changes.
set -euo pipefail

if [[ "${PIGEON_SKIP_FFI_BUILD:-0}" == "1" ]]; then
  echo "==> Skipping PigeonFFI rebuild (using prebuilt artifacts)"
  exit 0
fi

# Xcode scheme actions use a minimal, non-login PATH. Add the standard Rust and
# Homebrew locations explicitly so this script behaves the same from Xcode,
# Terminal, and CI without sourcing user shell configuration.
CARGO_BIN_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
export PATH="$CARGO_BIN_DIR:/opt/homebrew/bin:/usr/local/bin:$PATH"

for tool in rustup cargo xcodebuild protoc protoc-gen-swift; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: Required build tool '$tool' was not found in PATH." >&2
    exit 1
  fi
done

cd "$(dirname "$0")"
CRATE_DIR="$(pwd)"
LIB_NAME="libpigeon_ffi.a"
PACKAGE_DIR="$CRATE_DIR/../Pigeon/PigeonFFI"
BUILD_DIR="$CRATE_DIR/../target"
APPLE_DEPLOYMENT_TARGET="26.0"
# Cargo does not include Apple's deployment-target environment variables in its
# artifact fingerprint. Keep these objects in a versioned target directory so a
# prior host build cannot leak a newer minimum OS into the XCFramework.
APPLE_BUILD_DIR="$BUILD_DIR/apple-$APPLE_DEPLOYMENT_TARGET"
GEN_DIR="$(mktemp -d)"
trap 'rm -rf "$GEN_DIR"' EXIT

# Pigeon ships Apple-Silicon-only (it runs as a Mac-designed-for-iPad build and
# all iOS devices are arm64), so we build arm64 slices only — no x86_64 (Intel
# simulator / Intel Mac). That keeps the committed XCFramework small. Add the
# x86_64 targets back here if Intel-simulator support is ever needed.
DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGET="aarch64-apple-ios-sim"
# The macOS slice exists only so `swift test --package-path Pigeon/PigeonFFI` can link
# and run the round-trip tests on the host; the iOS app uses device/sim slices.
MAC_TARGET="aarch64-apple-darwin"

echo "==> Ensuring Rust targets are installed"
rustup target add "$DEVICE_TARGET" "$SIM_TARGET" "$MAC_TARGET"

echo "==> Building release static libs (symbols stripped via the release profile)"
for target in "$DEVICE_TARGET" "$SIM_TARGET" "$MAC_TARGET"; do
  if [[ "$target" == "$MAC_TARGET" ]]; then
    MACOSX_DEPLOYMENT_TARGET="$APPLE_DEPLOYMENT_TARGET" \
      CARGO_TARGET_DIR="$APPLE_BUILD_DIR" \
      cargo build --locked --release --target "$target" --lib
  else
    IPHONEOS_DEPLOYMENT_TARGET="$APPLE_DEPLOYMENT_TARGET" \
      CARGO_TARGET_DIR="$APPLE_BUILD_DIR" \
      cargo build --locked --release --target "$target" --lib
  fi
done

DEVICE_LIB="$APPLE_BUILD_DIR/$DEVICE_TARGET/release/$LIB_NAME"
SIM_LIB="$APPLE_BUILD_DIR/$SIM_TARGET/release/$LIB_NAME"
MAC_LIB="$APPLE_BUILD_DIR/$MAC_TARGET/release/$LIB_NAME"

echo "==> Generating Swift bindings + C headers (matched generator)"
# --library mode reads the namespace/metadata straight from the built dylib so
# the generator and the linked uniffi version can never drift apart.
cargo run --locked --bin uniffi-bindgen -- generate \
  --library "$DEVICE_LIB" \
  --language swift \
  --out-dir "$GEN_DIR"

# uniffi emits: pigeon_ffi.swift, pigeon_ffiFFI.h, pigeon_ffiFFI.modulemap.
# The .h + .modulemap describe the C module the XCFramework vends; the .swift is
# compiled as ordinary source in the PigeonFFI SPM target.
HEADERS_DIR="$GEN_DIR/headers"
mkdir -p "$HEADERS_DIR"
mv "$GEN_DIR"/*.h "$HEADERS_DIR/"
# XCFramework requires the modulemap to be named module.modulemap.
mv "$GEN_DIR"/*.modulemap "$HEADERS_DIR/module.modulemap"

echo "==> Assembling PigeonFFIBindings.xcframework"
rm -rf "$PACKAGE_DIR/PigeonFFIBindings.xcframework"
xcodebuild -create-xcframework \
  -library "$DEVICE_LIB" -headers "$HEADERS_DIR" \
  -library "$SIM_LIB" -headers "$HEADERS_DIR" \
  -library "$MAC_LIB" -headers "$HEADERS_DIR" \
  -output "$PACKAGE_DIR/PigeonFFIBindings.xcframework"

echo "==> Refreshing generated Swift bindings in PigeonFFI"
GENERATED_SWIFT_DIR="$PACKAGE_DIR/Sources/PigeonFFI/Generated"
# Generated filenames follow proto source filenames. Remove the exact generated
# tree so schema renames cannot leave duplicate Swift types behind.
rm -rf "$GENERATED_SWIFT_DIR"
mkdir -p "$GENERATED_SWIFT_DIR"
cp "$GEN_DIR"/*.swift "$GENERATED_SWIFT_DIR/"

echo "==> Generating Swift protobuf bindings"
protoc \
  --proto_path="$CRATE_DIR/../proto" \
  --swift_out="$GENERATED_SWIFT_DIR" \
  "$CRATE_DIR/../proto/pigeon/wire/v1/identity.proto" \
  "$CRATE_DIR/../proto/pigeon/wire/v1/pairwise.proto" \
  "$CRATE_DIR/../proto/pigeon/wire/v1/transport.proto" \
  "$CRATE_DIR/../proto/pigeon/wire/v1/group.proto" \
  "$CRATE_DIR/../proto/pigeon/wire/v1/client.proto"

echo "==> Writing PigeonFFIBindings.sha256"
# A tracked manifest of the build output, so a changed FFI surface shows up in
# `git diff` even though the artifacts themselves are gitignored. Verify a local
# build with `shasum -a 256 -c PigeonFFIBindings.sha256` from the package dir.
# Only deterministic files are listed. The static libs embed absolute toolchain
# and registry paths, so their hashes differ per machine; xcodebuild writes the
# Info.plist library entries in an unstable order between runs.
MANIFEST="$PACKAGE_DIR/PigeonFFIBindings.sha256"
(
  cd "$PACKAGE_DIR"
  find PigeonFFIBindings.xcframework Sources/PigeonFFI/Generated -type f ! -name '*.a' ! -name Info.plist ! -name .DS_Store \
    | LC_ALL=C sort \
    | while IFS= read -r file; do shasum -a 256 "$file"; done
) > "$MANIFEST.tmp"
mv "$MANIFEST.tmp" "$MANIFEST"

echo "==> Done: $PACKAGE_DIR/PigeonFFIBindings.xcframework"
