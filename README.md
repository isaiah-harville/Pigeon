# Pigeon

Pigeon is an offline, end-to-end encrypted Bluetooth mesh messaging app for Apple
platforms.

The project is early-stage: identity persistence and cryptographic
building blocks exist, while transport, pairing, persistence, and production UI
are still under construction.

## Repository Layout

- `Pigeon/` - SwiftUI app and Xcode project.
- `Pigeon/Pigeon/Core/Identity/` - long-term device identity, Keychain storage,
  public key fingerprints, and safety-number derivation.
- `PigeonCrypto/` - standalone Swift package for protocol primitives and Double
  Ratchet work.
- `docs/` - design and security notes for humans and coding agents.

## Common Commands

```sh
swift test --package-path PigeonCrypto
xcodebuild -list -project Pigeon/Pigeon.xcodeproj
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS'
```

## Security Status

This code is not audited and must not be treated as production-secure yet. The
crypto package delegates primitive operations to CryptoKit, but protocol
composition, transport metadata, replay handling, persistence, and UI safety
flows still need careful review.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).
