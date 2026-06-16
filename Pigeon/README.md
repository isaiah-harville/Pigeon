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

The app links the MIT-licensed `PigeonCrypto` and `PigeonMesh` packages. The
AGPL relay server is a separate network service and is not linked into the app.
