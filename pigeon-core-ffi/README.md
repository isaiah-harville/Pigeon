# pigeon-core-ffi

UniFFI bindings that expose [`pigeon-core`](../pigeon-core) (Pigeon's Olm/
`vodozemac` messaging core) to Swift. This crate is the only place that links
UniFFI, so `pigeon-core` itself stays free of any bindings coupling.

The FFI surface is deliberately thin: bundles and Olm messages cross as opaque
bytes, and the only stateful objects are `FfiAccount` and `FfiSession`. The
identity binding and prekey signatures are still verified inside Rust, so a
session is only ever returned for a peer whose Ed25519 identity authenticated
the channel.

## Build artifact, not source

`build-xcframework.sh` produces two things the Swift side consumes:

- `../PigeonCore/PigeonCoreFFI.xcframework` — the compiled Rust (arm64 iOS
  device + simulator + macOS slices).
- `../PigeonCore/Sources/PigeonCore/Generated/*.swift` — the generated UniFFI
  Swift bindings.

**Both are gitignored build artifacts** — regenerated from `src/lib.rs` rather
than version-controlled. So after cloning, or after changing `src/lib.rs`, run:

```sh
bash pigeon-core-ffi/build-xcframework.sh
```

CI regenerates them the same way before building the app or running the
`PigeonCore` Swift tests, so a change to the FFI surface is always reflected —
there is no committed copy that can go stale.

## Build only arm64

Pigeon ships Apple-Silicon-only (a Mac-designed-for-iPad build; all iOS devices
are arm64), so the script builds arm64 slices only — no x86_64.

## Tests

```sh
cargo test                              # Rust-side FFI seam round-trip
swift test --package-path ../PigeonCore # same, through the generated Swift
```
