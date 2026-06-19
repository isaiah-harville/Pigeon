# Pigeon App

The `Pigeon/` directory contains the iOS SwiftUI app and Xcode project.

## Structure

- `Pigeon.xcodeproj` — Xcode project, scheme `Pigeon`.
- `Pigeon/App/` — app entry point and top-level scene setup.
- `Pigeon/Core/Identity/` — Ed25519 identity, Keychain storage, fingerprints,
  and safety numbers.
- `Pigeon/Core/Contacts/` — contact model and QR contact-card wire format.
- `Pigeon/Core/Session/` — central session coordinator, Noise handshakes,
  per-contact `SecureSession`s, conversations, and messaging.
- `Pigeon/Core/Transport/` — BLE, relay, composite transport, relay settings,
  and relay latency measurement.
- `Pigeon/Core/Mesh/` — mesh service over any `Transport`.
- `Pigeon/Core/Storage/` — encrypted storage and vault key management.
- `Pigeon/Features/` — SwiftUI feature screens.

## Build

```sh
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO
```

The app source is available for transparency, review, and local development
under the source-available [LICENSE](LICENSE). It is not open source:
commercial use, redistribution as an app, and App Store/TestFlight publication
require permission from the Pigeon maintainers.

The app links the `PigeonCore` package (the Rust `pigeon-core` messaging core,
bridged via UniFFI and shipped as an XCFramework) and the Swift `PigeonMesh`
package. `pigeon-core`, `PigeonMesh`, and `pigeon-relay` are AGPL-3.0-only so
reusable messaging core code cannot be taken closed.
