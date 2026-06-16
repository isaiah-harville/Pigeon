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
- `PigeonCrypto/` - standalone Swift package for Noise, Double Ratchet, and
  protocol primitives.
- `PigeonMesh/` - standalone Swift package for fragmentation, mesh packets,
  deduplication, TTL, and session envelopes.
- `PigeonRelay/` - Rust zero-knowledge relay server.
- `docs/` - MkDocs source for design, security, roadmap, and source maps.

## Common Commands

```sh
swift test --package-path PigeonCrypto
swift test --package-path PigeonMesh
xcodebuild -list -project Pigeon/Pigeon.xcodeproj
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS'
cargo test --manifest-path PigeonRelay/Cargo.toml
uv run mkdocs build --strict
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

Pigeon is fully open source under a split chosen so the app stays freely
distributable (incl. the App Store) while the network relay stays strongly
copyleft:

- **The iOS app** (this repo, root [LICENSE](LICENSE)), **[`PigeonCrypto/`](PigeonCrypto/LICENSE)**,
  and **[`PigeonMesh/`](PigeonMesh/LICENSE)** — **MIT**. Permissive and App
  Store–compatible; the app links only these.
- **[`PigeonRelay/`](PigeonRelay/LICENSE)** — **GNU AGPL-3.0-only**. It's a standalone
  network server (not linked into the app), so AGPL's network-source-availability
  (§13) applies to anyone running a modified relay, with no effect on the app.

Source is always available either way. See
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) §5.5.
