# CLAUDE.md

## Project Mission

Pigeon is a secure, offline-capable messaging application that can use local
mesh transports and federated relays. It should keep messages private across all
transports while still making peer identity and verification understandable to
ordinary users.

Security is a product requirement, not a later polish step. Favor boring,
auditable code over clever abstractions.

## Licensing Policy

Keep the reusable protocol, cryptography, mesh, and relay packages open source
and copyleft. `pigeon-core`, `PigeonMesh`, and `PigeonRelay` are
`AGPL-3.0-only` so modified protocol/network code offered to users cannot be
taken closed. The iOS app and app-specific code are source-available but not
open source; commercial use, redistribution as an app, and App Store/TestFlight
publication require permission from the Pigeon maintainers.

## Current Architecture

The repo has the **app** (`Pigeon/`) plus three packages — `pigeon-core/`
(Rust), `PigeonMesh/` (Swift), and `PigeonRelay/` (Rust) — and `PigeonCore/`,
the thin Swift package that vends the generated FFI bindings + XCFramework.

**Rust migration (#79–#83):** the pairwise messaging core is the Rust
`pigeon-core`, built on Olm (via the audited `vodozemac` crate) — not a
clean-room Noise XX + X3DH + Double Ratchet. The iOS app reaches it through a
UniFFI bridge (`pigeon-core-ffi`) packaged as `PigeonCore`'s XCFramework (#80,
done). The old Swift `PigeonCrypto` package has been deleted; do not reintroduce
it. The remaining migration work is the shared protobuf wire format (#81) and
follow-ups (#82–#83).

- `Pigeon/` contains the SwiftUI app and Xcode project (`Pigeon/Pigeon.xcodeproj`,
  scheme `Pigeon`). Source lives under `Pigeon/Pigeon/`, split into `Core/`
  (model/logic) and `Features/` (SwiftUI views).
- `pigeon-core/` is a standalone Rust crate (`AGPL-3.0-only`) — the pairwise
  messaging core built on Olm/`vodozemac`. It keeps Pigeon's identity binding (a
  long-term Ed25519 key signs Olm's Curve25519 identity key) on top of Olm's
  session establishment + Double Ratchet. It is NOT a Cargo-workspace member of
  `PigeonRelay`.
- `pigeon-core-ffi/` is the UniFFI crate (the only crate that links UniFFI, so
  `pigeon-core` stays binding-free). `build-xcframework.sh` builds the Apple
  static libs, generates the Swift bindings + protobuf, and assembles
  `PigeonCore/PigeonCoreFFI.xcframework`. The XCFramework and generated bindings
  are build artifacts (gitignored) — regenerate them, don't commit them.
- `PigeonCore/` is the Swift package the app links: a `binaryTarget` for the
  XCFramework plus a thin Swift facade (`PigeonAccount`, `PigeonSession`,
  `PigeonIdentityBundle`, `PigeonPrekeyBundle`, contact-card codec) over the
  generated bindings.
- `PigeonMesh/` is a dependency-free, platform-agnostic Swift package for
  transport/mesh logic (packet framing, fragmentation/reassembly over small BLE
  MTUs, store-and-forward routing). The CoreBluetooth driver lives in the app and
  feeds bytes through this package — `PigeonMesh` itself has no radio dependency.
- `PigeonRelay/` is the Rust (axum/tokio) zero-knowledge relay server; ships as a
  Docker image. See the Remote Delivery section below.

### Repository map (where things live)

App `Core/`:
- `Core/Identity/` — long-term Ed25519 identity keys (`IdentityKey`), Keychain
  persistence (`KeychainStore`), `IdentityManager`, fingerprints, and
  `SafetyNumber` generation.
- `Core/Session/` — `SessionManager` (`@MainActor @Observable`) is the central
  coordinator: owns one Olm `PigeonSession` per contact, drives async-first
  establishment, contacts, conversations, and bridges to transports. It is split
  across `SessionManager.swift`, `+Messaging.swift`, `+Delivery.swift`,
  `+Reactions.swift`, and `+UI.swift` (UI passthroughs).
- `Core/Contacts/` — `Contact` and `ContactCard` (the QR/scan payload: identity
  bundle + display name + advertised relay URLs + relay signature).
- `Core/Transport/` — `Transport` protocol, `CompositeTransport` (mesh + relay),
  `RelayTransport`, `RelaySettings`, `PeerTransport`, `BluetoothConstants`.
- `Core/Mesh/` — `MeshService` (CoreBluetooth driver feeding `PigeonMesh`).
- `Core/Storage/` — `Vault` and `EncryptedStore` (encrypted local persistence).
- `Core/Notifications/` — `MessageNotifier`.

App `Features/`: `Onboarding/` (`UnlockView`, `OnboardingNameView`), `Home/`
(`ChatsListView`, `MenuView`, `RelaySettingsView`), `Chat/` (`ChatView`),
`Contacts/` (`AddContactView` = scan/paste flow, `IdentityQRView` = show my QR,
`QRScanner`, `QRCode`), `Components/`.

`pigeon-core/src/`: `identity.rs` (`IdentityKeypair` + `IdentityBundle` binding),
`account.rs` (`Account`: Ed25519 identity + Olm account + prekeys + persistence),
`prekey.rs` (`PrekeyBundle`), `session.rs` (`Session`, `Initiation`),
`wire.rs` (protobuf encode/decode for the `pigeon.wire.v1` schema), `error.rs`.
The shared schema is `proto/pigeon/wire/v1/pigeon_wire.proto`. Behavioral tests
in `pigeon-core/tests/pairwise.rs`.

`PigeonCore/Sources/PigeonCore/`: `PigeonCore.swift` (the Swift facade);
`Generated/` (UniFFI + protobuf bindings — gitignored build output).

`PigeonMesh/Sources/PigeonMesh/`: `MeshPacket`, `SessionEnvelope`, `Fragmentation`.

Tests live in `pigeon-core/tests/`, `pigeon-core-ffi/src/` (Rust FFI seam),
`PigeonCore/Tests/` (Swift round-trip), `PigeonMesh/Tests/`, and the app's
`Pigeon/PigeonTests/` target. Docs of note: `docs/SECURITY_MODEL.md`,
`docs/HOW_IT_WORKS.md`, `docs/ROADMAP.md`.

## Security Invariants

- Never log private keys, message keys, root keys, chain keys, plaintext message
  bodies, safety-number seeds, or raw Keychain values.
- Long-term private identity material must stay in the Keychain and must not sync
  through iCloud or backups.
- Prefer CryptoKit or audited platform APIs. Do not implement cryptographic math.
- Treat Bluetooth transport metadata as observable by attackers unless explicitly
  protected.
- Authenticate all protocol headers and routing metadata that affect decryption,
  replay handling, trust, or message ordering.
- Use explicit domain separation strings for every KDF context.
- Do not silently reset identity or trust state. User-facing identity changes
  must be deliberate and obvious.
- For security-affecting code, add or update tests before considering the work
  complete.

## Coding Style

- Follow existing Swift style: small types, explicit names, focused comments.
- Keep app code and reusable crypto/package code separated.
- Preserve Swift 6 concurrency assumptions. Add `Sendable` only when the type
  really is safe to move across isolation boundaries.
- Keep wire encodings deterministic and documented.
- Avoid broad refactors while changing cryptographic or identity code.
- Use `rg` for search and read nearby code before editing.

## Testing And Verification

Run the narrowest useful command first, then broaden when the change touches
shared behavior:

```sh
cargo test --manifest-path pigeon-core/Cargo.toml      # Rust messaging core
cargo test --manifest-path pigeon-core-ffi/Cargo.toml  # FFI seam
bash pigeon-core-ffi/build-xcframework.sh              # regenerate bindings + XCFramework
swift test --package-path PigeonCore                   # Swift round-trip across the FFI
swift test --package-path PigeonMesh
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS'
cargo test --manifest-path PigeonRelay/Cargo.toml      # relay (Rust)
```

Useful discovery command:

```sh
xcodebuild -list -project Pigeon/Pigeon.xcodeproj
```

If a command fails because a sandbox blocks SwiftPM or Clang cache writes under
the user home directory, report that clearly and rerun only with explicit user
approval.

## Expected Agent Workflow

Be conservative with tokens.

1. Read `README.md`, this file, and any relevant files under `docs/`.
2. Inspect the code paths involved before planning a change.
3. For crypto, identity, trust, or transport behavior, identify the attacker
   model and state which invariant is being preserved.
4. Make small, reviewable edits.
5. Run tests/builds that match the risk of the change.
6. In the final response, summarize what changed, what was verified, and any
   remaining security caveat.

## Remote Delivery (decided)

An **opt-in, federated, zero-knowledge relay** is an approved part of the
architecture for reaching peers out of local range (decision recorded
2026-06-16). It is a blind ciphertext mailbox: clients address delivery to a
recipient's advertised relay(s); the relay never sees plaintext and is never
trusted for confidentiality, authentication, or integrity. The relay server
lives in this repo (`PigeonRelay/`), ships as a Docker image, and is federated from the
start (many independent relays, chosen per user — no server-to-server protocol).
Local delivery and relay delivery are both first-class transports carrying the
same end-to-end ciphertext. See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
§6.1.

## Do Not Do

- Do not add analytics, telemetry, or cloud sync, and do not add *new* network
  services beyond the decided relay (above), without an explicit product decision.
- The relay must stay zero-knowledge: never give it plaintext, keys, linkable
  logs, or any field that lets it read, link, or forge content.
- Do not introduce unaudited crypto dependencies casually.
- Do not weaken Keychain accessibility for convenience.
- Do not paper over authentication failures with retries or fallback plaintext.
- Do not store secrets in `UserDefaults`, files, logs, previews, screenshots, or
  test fixtures.
- Do not claim the app is production-secure or audited.
