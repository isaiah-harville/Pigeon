# Pigeon

Pigeon is an end-to-end encrypted mesh messaging app for iOS.

**It is fully offline and serverless whenever peers can reach each other
locally** — over a Bluetooth Low Energy mesh (with local Wi-Fi planned). When a
peer is out of local range, Pigeon can *optionally* deliver over the internet
through a **zero-knowledge relay** that only ever stores and forwards ciphertext.
Messages are end-to-end encrypted regardless of how they travel; no transport,
relay, or mesh hop can read them.

The project is early-stage: identity persistence and cryptographic
building blocks exist, while transport, pairing, persistence, and production UI
are still under construction.

## How devices reach each other

Pigeon sends the *same* end-to-end-encrypted ciphertext over any available
transport (they share one pluggable `Transport` abstraction and run
concurrently):

- **Bluetooth LE mesh** — in-range, fully offline and serverless. The default
  and the privacy floor: no server is ever involved.
- **Local Wi-Fi** (planned) — same-network reach, higher bandwidth, still
  serverless.
- **Relay** (in progress) — for peers who are out of local range and on
  different networks (e.g. cellular). A self-hostable, zero-knowledge mailbox
  forwards ciphertext addressed by public key. It **cannot read messages**, but
  it does see connection metadata (who connects, when). Opt-in; see the security
  model for the trade-off.

> Remote delivery is the one place Pigeon is not serverless — it can't be, by the
> nature of the internet (see [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
> §6). Stay in Bluetooth range and Pigeon never touches a server.

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

## License

Pigeon is fully open source under a split chosen so the app stays freely
distributable (incl. the App Store) while the network relay stays strongly
copyleft:

- **The iOS app** (this repo, root [LICENSE](LICENSE)), **[`PigeonCrypto/`](PigeonCrypto/LICENSE)**,
  and **[`PigeonMesh/`](PigeonMesh/LICENSE)** — **MIT**. Permissive and App
  Store–compatible; the app links only these.
- **[`relay/`](relay/LICENSE)** — **GNU AGPL-3.0-only**. It's a standalone
  network server (not linked into the app), so AGPL's network-source-availability
  (§13) applies to anyone running a modified relay, with no effect on the app.

Source is always available either way. See
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) §5.5.
