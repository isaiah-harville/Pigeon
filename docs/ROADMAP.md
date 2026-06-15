# Pigeon — Roadmap

Pigeon is a fully offline, open-source, privacy/security-first messenger.
Messages travel end-to-end encrypted over a local **Bluetooth Low Energy mesh** —
no servers, no accounts, no internet. See [SECURITY_MODEL.md](SECURITY_MODEL.md)
for the security design and audit-readiness tracking.

## Locked architecture decisions

- **Platforms:** iOS-first; macOS kept buildable for fast dev/testing. visionOS
  deferred.
- **Topology:** BLE mesh relay — encrypted store-and-forward; relays forward
  ciphertext they cannot read.
- **Crypto:** Signal-grade — Noise handshake + Double Ratchet — implemented
  clean-room over CryptoKit in the standalone `PigeonCrypto` package (chosen over
  libsignal: AGPL/App-Store conflict, server-coupled design, auditability).
- **Storage:** encrypted-at-rest (key tied to biometrics/passcode) + optional
  ephemeral (no-persistence) mode.
- **Identity:** on-device Curve25519 keypair (no accounts/phone numbers); public
  key fingerprint is the address; trust via in-person QR exchange + safety number.

## Module layout

- `PigeonCrypto/` — package: Primitives, DoubleRatchet, NoiseHandshake,
  SecureSession (identity-agnostic, CLI-tested).
- `PigeonMesh/` — package: transport/mesh logic — Fragmentation today; mesh
  routing next (dependency-free, CLI-tested).
- `Pigeon/` (app) — Identity (Keychain), CoreBluetooth transport, and (later)
  storage + UI. Links both packages.

## Phases

| Phase | Scope | Status |
|------|-------|--------|
| 1 | **Identity** — Curve25519 key in Keychain, fingerprint, safety number | ✅ done |
| 2 | **Crypto core** — primitives, Double Ratchet, Noise XX, SecureSession (44 tests) | ✅ done |
| 3 | **BLE transport** — dual-role CoreBluetooth, GATT, fragmentation/reassembly | ✅ link verified on two devices |
| 3b | **Encrypt the link** — SecureSession over mesh, identity binding, QR exchange, encrypted chat UI | ✅ built (awaiting two-device test) |
| 4 | **Mesh** — packet format, TTL, duplicate-suppression, store-and-forward | ✅ dedup + flood relay + per-contact store-and-forward queue (persisted) |
| 5 | **Encrypted storage** — at-rest encryption + ephemeral mode | ✅ biometric-gated Vault, EncryptedStore, per-chat ephemeral mode |
| 6 | **UI** — onboarding, QR contact verification, real chat | ⬜ |
| 7 | **Hardening** — traffic-analysis resistance, security review, audit prep | ⬜ |

## Tracked follow-ups / known gaps

Carried so we don't lose them; several are also audit blockers (see
SECURITY_MODEL.md → Audit Readiness).

- **Duplicate delivery:** ✅ resolved — mesh dedup (seen-cache by packet id)
  delivers each message once across multiple BLE paths.
- **Identity ↔ Noise-static binding:** ✅ resolved — IdentityBundle signs the
  X25519 static key with the Ed25519 identity; SessionManager rejects any
  session whose handshake static key doesn't match the verified bundle.
- **Official Noise test vectors:** current tests prove self-consistency only;
  add byte-level conformance vectors. **Audit blocker.**
- **Async first contact:** interactive Noise for now; serverless X3DH-style
  prekeys (in QR / gossiped) deferred.
- **BLE MTU:** raise the fixed conservative fragment size to the negotiated MTU
  per connection; consider write-without-response for throughput.
- **Connection topology:** dedupe the two-way central/peripheral link per pair.
- **Key zeroization, constant-time compares, logging discipline** — see
  SECURITY_MODEL.md.
- **External security audit** before any real-world "secure" claim.
- **Linting/formatting debt:** SwiftLint/SwiftFormat pre-commit hooks currently
  fail (line length, force-unwrap, identifier names, etc.); commits use
  `--no-verify` for now. Do a formatting/lint cleanup pass.
- **Re-handshake DoS:** session envelopes are unauthenticated at the mesh layer,
  so a spoofed `rehandshakeRequest`/handshake could force a session reset (no
  content breach — the binding check still holds). Rate-limit / harden later.
- **Store-and-forward:** queued messages have no age expiry yet; relay-level
  store-and-forward (holding *others'* packets for later) is still future work.

## Beyond these phases

Longer-term direction — **group chats** and **long-distance / non-Bluetooth
secure transport** — is planned in [FUTURE_ROADMAP.md](FUTURE_ROADMAP.md).

## Standing principles

- Security-critical code stays small, dependency-free, and auditable; compose
  CryptoKit primitives rather than reimplement them.
- Commit incrementally; each commit should build.
- Be honest in docs about what is and isn't verified — nothing is "secure" until
  audited.
