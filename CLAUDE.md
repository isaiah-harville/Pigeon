# CLAUDE.md

## Project Mission

Pigeon is a secure, offline-capable messaging application that can use local
mesh transports and federated relays. It should keep messages private across all
transports while still making peer identity and verification understandable to
ordinary users.

Security is a product requirement, not a later polish step. Favor boring,
auditable code over clever abstractions.

## Current Architecture

- `Pigeon/` contains the SwiftUI app and Xcode project.
- `Pigeon/Pigeon/Core/Identity/` owns long-term Ed25519 identity keys, Keychain
  persistence, public-key fingerprints, and safety-number generation.
- `PigeonCrypto/` is a standalone Swift package for cryptographic protocol code.
  Keep it dependency-free unless there is a strong security reason.
- `PigeonCrypto/Sources/PigeonCrypto/Primitives.swift` wraps CryptoKit primitives.
- `PigeonCrypto/Sources/PigeonCrypto/DoubleRatchet.swift` implements ratchet
  state and message encryption/decryption.

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
swift test --package-path PigeonCrypto
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS'
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
lives in this repo (`relay/`), ships as a Docker image, and is federated from the
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
