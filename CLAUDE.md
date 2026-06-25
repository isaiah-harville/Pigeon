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
and copyleft. `pigeon-core`, `pigeon-mesh`, and `pigeon-relay` are
`AGPL-3.0-only` so modified protocol/network code offered to users cannot be
taken closed. The iOS app and app-specific code are source-available but not
open source; commercial use, redistribution as an app, and App Store/TestFlight
publication require permission from the Pigeon maintainers.

## Current Architecture

The repo has the **app** (`Pigeon/`) plus three Rust crates — `pigeon-core/`,
`pigeon-mesh/`, and `pigeon-relay/` — and `Pigeon/PigeonFFI/`, the thin Swift
package that vends the generated FFI bindings + XCFramework. The xcodeproject uses file-system-scnchronized groups (auto-include).

**Rust migration (#79–#83):** the pairwise messaging core is the Rust
`pigeon-core`, built on Olm (via the audited `vodozemac` crate) — not a
clean-room Noise XX + X3DH + Double Ratchet. The iOS app reaches it through a
UniFFI bridge (`pigeon-ffi`) packaged as the `PigeonFFI` package's XCFramework
(#80, done). The old Swift `PigeonCrypto` package has been deleted; do not
reintroduce it. The remaining migration work is the shared protobuf wire format
(#81) and follow-ups (#82–#83).

- `Pigeon/` contains the SwiftUI app and Xcode project (`Pigeon/Pigeon.xcodeproj`,
  scheme `Pigeon`). Source lives under `Pigeon/Pigeon/`, split into `Core/`
  (model/logic) and `Features/` (SwiftUI views).
- `pigeon-core/` is a standalone Rust crate (`AGPL-3.0-only`) — the pairwise
  messaging core built on Olm/`vodozemac`. It keeps Pigeon's identity binding (a
  long-term Ed25519 key signs Olm's Curve25519 identity key) on top of Olm's
  session establishment + Double Ratchet. It is NOT a Cargo-workspace member of
  `pigeon-relay`.
- `pigeon-ffi/` is the UniFFI crate (the only crate that links UniFFI, so
  `pigeon-core` and `pigeon-mesh` stay binding-free). `build-xcframework.sh`
  builds the Apple static libs, generates the Swift bindings + protobuf, and
  assembles `Pigeon/PigeonFFI/PigeonFFIBindings.xcframework`. The XCFramework and
  generated bindings are build artifacts (gitignored) — regenerate them, don't
  commit them.
- `Pigeon/PigeonFFI/` is the Swift package the app links (module `PigeonFFI`): a
  `binaryTarget` for the XCFramework plus a thin Swift facade (`PigeonAccount`,
  `PigeonSession`,
  `PigeonIdentityBundle`, `PigeonPrekeyBundle`, contact-card codec) over the
  generated bindings.
- `pigeon-mesh/` is a dependency-free, platform-agnostic Rust crate
  (`AGPL-3.0-only`) for transport/mesh logic (packet framing, fragmentation/
  reassembly over small BLE MTUs, dedup/TTL flood routing, and the
  identity-addressed session envelope). It carries opaque ciphertext and performs
  no cryptography, so every client shares one wire format by linking it. The iOS
  app reaches it through the same UniFFI bridge as `pigeon-core`; the
  CoreBluetooth driver lives in the app and feeds bytes through it.
- `pigeon-relay/` is the Rust (axum/tokio) zero-knowledge relay server; ships as a
  Docker image. See the Remote Delivery section below.


## vodozemac 0.10 API facts (save future spelunking)

- `SessionConfig::version_2()` does **not** exist — use `SessionConfig::default()` (both sides).
- `Session::encrypt` returns `Result<OlmMessage, EncryptionError>`; `decrypt(&OlmMessage)`.
- `Curve25519PublicKey::from_bytes([u8;32])` is **infallible**.
- `fallback_key()` / `one_time_keys()` return only **unpublished** keys (empty after
  `mark_keys_as_published()` and after a pickle round-trip) — that's why `Account` stores
  the fallback public bytes itself and `import()` takes them.
- ed25519-dalek 2.x: `SigningKey::from_bytes(&[u8;32])`, `verify_strict`. Used `getrandom`
  (not `rand`) for the seed to dodge the rand_core version skew.
- Olm message wire encoding lives in `pigeon-core/src/wire.rs`
  (`encode_olm_message`/`decode_olm_message`, `Initiation::encode/decode`); the
  FFI just calls `.encode()`/`.decode()` — no hand-rolled bytes in the FFI.


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
- `Core/Mesh/` — `MeshService` (CoreBluetooth driver feeding `pigeon-mesh` via
  the FFI).
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

`Pigeon/PigeonFFI/Sources/PigeonFFI/`: `PigeonCore.swift` (the crypto facade),
`PigeonMesh.swift` (the mesh facade over the generated bindings); `Generated/`
(UniFFI + protobuf bindings — gitignored build output).

`pigeon-mesh/src/`: `packet.rs` (`MeshPacket`, `SeenCache`, `MeshRouter`),
`fragment.rs` (`Fragment`, `Fragmenter`, `Reassembler`), `envelope.rs`
(`SessionEnvelope`, `EnvelopeType`). Behavioral tests live in each module.

Tests live in `pigeon-core/tests/`, `pigeon-mesh/src/` (per-module),
`pigeon-ffi/src/` (Rust FFI seam), `Pigeon/PigeonFFI/Tests/` (Swift round-trip),
and the app's `Pigeon/PigeonTests/` target. Docs of note: `docs/SECURITY_MODEL.md`,
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
- Comments describe current behavior, not history: no issue/PR numbers (`(#42)`)
  and no "new"/"now"/"recently". Traceability lives in git and the PR.
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
cargo test --manifest-path pigeon-mesh/Cargo.toml      # Rust mesh (framing/routing/fragmentation)
cargo test --manifest-path pigeon-ffi/Cargo.toml       # FFI seam
bash pigeon-ffi/build-xcframework.sh                   # regenerate bindings + XCFramework
swift test --package-path Pigeon/PigeonFFI             # Swift round-trip across the FFI
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS'
cargo test --manifest-path pigeon-relay/Cargo.toml      # relay (Rust)
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
lives in this repo (`pigeon-relay/`), ships as a Docker image, and is federated from the
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
