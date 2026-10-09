#!/bin/sh

set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
package_dir="$repository_root/Pigeon/PigeonFFI"
manifest="$package_dir/PigeonFFIBindings.sha256"
xcframework="$package_dir/PigeonFFIBindings.xcframework"
generated_binding="$package_dir/Sources/PigeonFFI/Generated/pigeon_ffi.swift"

if [ ! -d "$xcframework" ] || [ ! -f "$generated_binding" ]; then
    echo "Generated FFI artifacts are absent; skipping integrity check."
    exit 0
fi

(
    cd "$package_dir"
    shasum -a 256 -c "$(basename -- "$manifest")"
)
