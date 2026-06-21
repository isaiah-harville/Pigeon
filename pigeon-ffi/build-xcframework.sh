#!/usr/bin/env bash
#
# Builds PigeonFFIBindings.xcframework from the pigeon-ffi crate and refreshes
# the generated Swift bindings in the sibling PigeonFFI package.
#
# Output:
#   ../Pigeon/PigeonFFI/PigeonFFIBindings.xcframework  (device + simulator static libs)
#   ../Pigeon/PigeonFFI/Sources/PigeonFFI/Generated/   (UniFFI + protobuf Swift)
#
# Re-run whenever the FFI surface in src/lib.rs changes.
set -euo pipefail

cd "$(dirname "$0")"
CRATE_DIR="$(pwd)"
LIB_NAME="libpigeon_ffi.a"
PACKAGE_DIR="$CRATE_DIR/../Pigeon/PigeonFFI"
BUILD_DIR="$CRATE_DIR/../target"
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
  cargo build --release --target "$target" --lib
done

DEVICE_LIB="$BUILD_DIR/$DEVICE_TARGET/release/$LIB_NAME"
SIM_LIB="$BUILD_DIR/$SIM_TARGET/release/$LIB_NAME"
MAC_LIB="$BUILD_DIR/$MAC_TARGET/release/$LIB_NAME"

echo "==> Generating Swift bindings + C headers (matched generator)"
# --library mode reads the namespace/metadata straight from the built dylib so
# the generator and the linked uniffi version can never drift apart.
cargo run --bin uniffi-bindgen -- generate \
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
mkdir -p "$PACKAGE_DIR/Sources/PigeonFFI/Generated"
cp "$GEN_DIR"/*.swift "$PACKAGE_DIR/Sources/PigeonFFI/Generated/"

echo "==> Generating Swift protobuf bindings"
protoc \
  --proto_path="$CRATE_DIR/../proto" \
  --swift_out="$PACKAGE_DIR/Sources/PigeonFFI/Generated" \
  "$CRATE_DIR/../proto/pigeon/wire/v1/pigeon_wire.proto"

echo "==> Done: $PACKAGE_DIR/PigeonFFIBindings.xcframework"
