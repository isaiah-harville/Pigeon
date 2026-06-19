# Pigeon

Pigeon is an end-to-end encrypted mesh messaging app for iOS.

Pigeon's goal is extreme privacy and security across multiple delivery methods.
Peers can exchange messages locally over a Bluetooth Low Energy mesh (with local
Wi-Fi planned), or use federated zero-knowledge relays when they are out of
local range. Messages are end-to-end encrypted regardless of how they travel; no
transport, relay, or mesh hop can read them.

The project is early-stage and pre-audit, but the main architecture is in
place: on-device identity, QR trust exchange, encrypted local storage, BLE mesh
delivery, per-contact encrypted sessions, and the first relay transport all
exist. The remaining work is mostly hardening, test depth, metadata reduction,
and product polish.

> **New here?** [**How Pigeon Works**](docs/HOW_IT_WORKS.md) is an illustrated,
> plain-language walkthrough of the whole system — keys, trust, the handshake,
> the ratchet, and every transport

## Project sites

- Main site: [pigeonwire.app](https://pigeonwire.app/)
- Documentation: [docs.pigeonwire.app](https://docs.pigeonwire.app/)
- Support: [pigeonwire.app/support](https://pigeonwire.app/support/)
- Privacy policy: [pigeonwire.app/privacy-policy](https://pigeonwire.app/privacy-policy/)

## How devices reach each other

Pigeon sends the *same* end-to-end-encrypted ciphertext over any available
transport (they share one pluggable `Transport` abstraction and run
concurrently):

- **Bluetooth LE mesh** — in-range, offline-capable local delivery with no
  server involved.
- **Local Wi-Fi** (planned) — same-network reach and higher bandwidth.
- **Relay** (in progress) — for peers who are out of local range and on
  different networks (e.g. cellular). A self-hostable, zero-knowledge mailbox
  forwards ciphertext addressed by public key. It **cannot read messages**, but
  it does see connection metadata (who connects, when). Opt-in; see the security
  model for the trade-off.

> Relays are an intentional federated transport option for remote delivery, not
> a downgrade from the local mesh. They trade some connection metadata for reach;
> message confidentiality and authenticity remain end-to-end.

## Repository Layout

- `Pigeon/` - SwiftUI app and Xcode project.
- `Pigeon/Pigeon/Core/Identity/` - long-term device identity, Keychain storage,
  public key fingerprints, and safety-number derivation.
- `pigeon-core/` - Rust pairwise messaging core (Olm via the audited `vodozemac`
  crate): the identity binding, prekeys, session establishment, and the
  `pigeon.wire.v1` protobuf wire format. The cross-platform messaging core.
- `pigeon-core-ffi/` - UniFFI bridge crate; `build-xcframework.sh` builds the
  Apple XCFramework and generates the Swift bindings the app links.
- `PigeonCore/` - Swift package wrapping that XCFramework (a `binaryTarget` plus
  a thin Swift facade); this is what the iOS app links for messaging crypto.
- `PigeonMesh/` - standalone Swift package for fragmentation, mesh packets,
  deduplication, TTL, and session envelopes.
- `pigeon-relay/` - Rust zero-knowledge relay server.
- `docs/` - MkDocs source for design, security, roadmap, and API docs.

## Common Commands

```sh
cargo test --manifest-path pigeon-core/Cargo.toml
cargo test --manifest-path pigeon-core-ffi/Cargo.toml
bash pigeon-core-ffi/build-xcframework.sh   # regenerate bindings + XCFramework
swift test --package-path PigeonCore
swift test --package-path PigeonMesh
xcodebuild -list -project Pigeon/Pigeon.xcodeproj
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS'
cargo test --manifest-path pigeon-relay/Cargo.toml
uv run --group docs mkdocs build --strict
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for review expectations, local tooling,
and the project policy for LLM/agent-assisted work.

## Security Status

This code is not audited and must not be treated as production-secure yet. The
crypto package delegates primitive operations to CryptoKit, but protocol
composition, transport metadata, replay handling, persistence, and UI safety
flows still need careful review.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## License

See [LICENSING.md](LICENSING.md) for the repository license map.
