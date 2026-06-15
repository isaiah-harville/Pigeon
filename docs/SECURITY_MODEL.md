# Pigeon — Security Model

> **Status: pre-release prototype. NOT independently audited.**
> This document describes the design and current implementation of Pigeon's
> security. It is a working model for implementation and review, **not** an
> audit report, and Pigeon should not yet be relied on against a real
> adversary. See [Audit Readiness](#audit-readiness--pre-audit-notes).

Pigeon is a fully offline, open-source messenger. Messages travel end-to-end
encrypted over a local **Bluetooth Low Energy mesh** — no servers, no accounts,
no internet, no Apple Push. Identity is a key pair on your device; there is
nothing to register and no central party to trust.

---

## 1. Goals

- **Confidentiality** of message contents from relay devices and passive radio
  observers.
- **End-to-end encryption** between conversation participants; intermediate mesh
  relays forward ciphertext they cannot read.
- **Mutual authentication** of peers via long-term identity keys.
- **Human-verifiable trust**: a safety number users compare out of band to
  detect impersonation / man-in-the-middle.
- **Forward secrecy** (a compromised key does not expose past messages) and
  **post-compromise security** (the channel heals after a compromise) at the
  conversation layer.
- **No cloud, server, or account dependency** for core messaging.
- **Auditability**: security-critical code is small, dependency-free, and
  readable.

## 2. Non-Goals (current prototype)

- Production-grade security guarantees (pending external audit).
- Anonymity against an adversary observing local Bluetooth radio.
- Strong metadata privacy (who talks to whom, when, message sizes/timing).
- Protection from a compromised or unlocked endpoint device.
- Asynchronous first contact (messaging a peer who has never been in range) —
  deferred; see §6.
- Multi-device identity sync.

---

## 3. Architecture Overview

```
┌──────────────────────────────────────────────┐
│ App (SwiftUI, iOS-first; macOS for dev)        │
│  onboarding · contacts/QR verify · chat        │
├──────────────────────────────────────────────┤
│ Storage (Phase 5)  encrypted-at-rest + ephemeral│
├──────────────────────────────────────────────┤
│ Mesh (Phase 4)  packet format · TTL · dedup ·   │
│                 store-and-forward relay          │
├──────────────────────────────────────────────┤
│ Transport (Phase 3)  CoreBluetooth central+      │
│                 peripheral · GATT · MTU chunking │
├──────────────────────────────────────────────┤
│ PigeonCrypto (package)  identity-agnostic crypto │
│   SecureSession → Noise_XX handshake +           │
│   Double Ratchet, over CryptoKit primitives      │
├──────────────────────────────────────────────┤
│ Identity (app)  Ed25519 key in Keychain,         │
│                 fingerprint, safety number       │
└──────────────────────────────────────────────┘
```

End-to-end encryption is performed by the two conversation endpoints
(`PigeonCrypto.SecureSession`). The mesh layer relays opaque ciphertext;
**relays learn routing/metadata but never plaintext.**

---

## 4. Identity & Trust

- Each device generates a long-term **Ed25519** identity key pair on first
  launch (`Curve25519.Signing` via CryptoKit).
- The private key is stored in the **Keychain** with
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: device-only, excluded from
  iCloud and backups, readable only while unlocked.
- **Secure Enclave is deliberately not used**: it supports only P-256, which is
  incompatible with the X25519/Ed25519 stack the protocols require.
- The public key's **SHA-256 fingerprint** is the device's address/handle.
- Public identities are exchanged **in person via QR code**. From a pair of
  public keys we derive a **60-digit safety number** (order-independent,
  iterated hashing) that users compare out of band to detect MITM.
- **Identity reset** generates a fresh key, irreversibly invalidating all
  existing trust relationships. This is, and must remain, user-visible.

> **Open binding issue (tracked):** the long-term key used by the Noise
> handshake is an **X25519 static** key, while the *identity* key is **Ed25519**.
> These must be cryptographically bound (the X25519 static signed by the Ed25519
> identity, and both carried in the QR payload) so that verifying the safety
> number actually authenticates the Noise channel. This binding is **not yet
> implemented**. See [Audit Readiness](#audit-readiness--pre-audit-notes).

---

## 5. Cryptographic Design

All primitives come from Apple **CryptoKit** (constant-time, audited). Pigeon
code composes them into protocols; it **never implements primitive algorithms**.

### 5.1 Primitives (`Primitives.swift`)
- **X25519** key agreement (`DHKeyPair`).
- **HKDF-SHA256** for the Double Ratchet root KDF (`KDF_RK`).
- **HMAC-SHA256** for the symmetric-key chain KDF (`KDF_CK`).
- **AES-256-GCM** for ratchet message encryption; each one-time message key is
  expanded via HKDF to a fresh 32-byte key + 12-byte nonce (so the (key,nonce)
  pair never repeats). The ratchet header is bound as associated data.

### 5.2 Handshake — `Noise_XX_25519_ChaChaPoly_SHA256` (`NoiseHandshake.swift`)
- Clean-room implementation of the Noise Protocol framework state machine
  (CipherState, SymmetricState, HandshakeState), pattern **XX**.
- **XX** chosen for mutual authentication without pre-shared knowledge of the
  peer's static key; both static keys are exchanged (initiator's encrypted) and
  exposed for verification against the QR identity.
- Cipher suite: **X25519** DH, **ChaCha20-Poly1305** AEAD, **SHA-256** hash,
  Noise's HKDF (HMAC-SHA256 extract/expand).
- Output: directional transport ciphers, the peer's static public key, and the
  handshake transcript hash.

### 5.3 Conversation — Double Ratchet (`DoubleRatchet.swift`)
- Clean-room implementation of the Signal Double Ratchet.
- Provides **forward secrecy** and **post-compromise security**.
- Tolerates **out-of-order and dropped** messages via bounded skipped-message-key
  storage (`maxSkip`, default 1000) — essential over a lossy BLE mesh.
- 40-byte authenticated header (DH ratchet key ‖ previous-chain length ‖ message
  number), folded into AEAD associated data, so header tampering breaks
  decryption.

### 5.4 Composition — `SecureSession.swift`
- Drives the Noise XX handshake, then transitions into a ratchet-backed channel.
- The responder ships its **initial ratchet public key** inside handshake message
  2's encrypted payload.
- The ratchet **root secret** is derived from the Noise transcript hash via
  HKDF-SHA256 (domain separated, info `"Pigeon.SessionRoot"`).
- Application wire format: `40-byte ratchet header ‖ AES-256-GCM ciphertext+tag`.
- Exposes `remoteStaticKey` for verification against the QR identity.

### 5.5 Why clean-room instead of libsignal
- **License:** libsignal is **AGPL-3.0**; linking it would make Pigeon AGPL and
  collides with App Store distribution terms (the VLC precedent).
- **Fit:** libsignal is coupled to Signal's server-mediated model (registration,
  prekey servers, sealed sender) — a poor match for serverless BLE mesh.
- **Auditability:** a focused Swift package over CryptoKit is something
  contributors can actually read, unlike a vendored Rust/C blob.
- **Risk boundary:** we implement *protocol composition*, not primitives, which
  is a far smaller and more checkable surface than implementing curve math.
  This does **not** remove the need for an external audit (§Audit Readiness).

---

## 6. Transport & Mesh

- **Transport (Phase 3, in progress):** CoreBluetooth, each device acting as both
  central and peripheral; a custom GATT service; message chunking/reassembly to
  fit BLE MTUs; framing.
- **Mesh (Phase 4):** packet format with TTL, duplicate-suppression (seen-cache),
  and **store-and-forward** relaying so messages hop toward out-of-range peers.
  Relays handle ciphertext only.
- **Session establishment is interactive for now:** two contacts must be in mesh
  contact to run the Noise handshake; thereafter ratchet messages relay
  asynchronously. **Async first contact** (X3DH-style serverless prekeys) is a
  planned later enhancement, with its own replay/exhaustion considerations.

---

## 7. Attacker Model

**Assume an attacker can:**
- Observe, record, replay, delay, drop, and reorder Bluetooth traffic.
- Operate or compromise relay devices in the mesh.
- Attempt pairing/identity impersonation and MITM.
- Tamper with any unauthenticated protocol field.
- Read app logs, crash reports, and unprotected on-disk state.
- Perform traffic analysis (timing, sizes, presence) on local radio.

**Assume an attacker cannot:**
- Break CryptoKit primitives (X25519, AES-GCM, ChaCha20-Poly1305, SHA-256, HMAC).
- Extract Keychain items from an uncompromised, locked device.
- Recover plaintext from a non-compromised endpoint after decryption.
- Defeat an out-of-band safety-number comparison performed honestly by users.

---

## 8. Known Limitations

- **Metadata is exposed.** BLE advertisements, packet timing, sizes, and mesh
  routing reveal communication patterns. No padding/cover traffic yet.
- **Endpoint trust.** A compromised/unlocked device defeats all guarantees.
- **No async first contact** (see §6).
- **No audit** (see below).
- **Key zeroization is limited** by CryptoKit/Swift value semantics; secret
  lifetimes are not yet minimized or wiped on a best-effort basis.

---

## Audit Readiness — Pre-Audit Notes

**Pigeon has NOT undergone an independent security audit.** No "secure" or
"private" claim should be treated as verified until it has. This section lists
what an auditor should examine and what must be resolved first. It is the
authoritative to-do list for reaching audit readiness.

### Must-fix before an audit is meaningful
1. **Bind Noise static ↔ Ed25519 identity (§4).** Today the QR/safety-number
   flow verifies the Ed25519 identity, but the Noise handshake authenticates an
   X25519 static key that is *not* cryptographically tied to it. Implement: a
   long-term X25519 static signed by the Ed25519 identity, both in the QR
   payload, with signature + binding verified at session establishment.
2. **Cross-validate Noise against the official test vectors.** Current tests
   prove our two ends interoperate (self-consistency); they do **not** prove
   byte-level conformance to `Noise_XX_25519_ChaChaPoly_SHA256`. Add the
   published vectors to the test suite.
3. **Handshake replay / freshness.** Define and test behavior for replayed or
   reordered handshake messages, including across the mesh's store-and-forward.

### Should-address
4. **Skipped-key DoS bound.** Review `maxSkip` (currently 1000) and the memory
   cost of stored skipped message keys under adversarial gaps.
5. **Key lifetime & zeroization.** Best-effort wiping of private keys, shared
   secrets, and message keys; minimize copies.
6. **Constant-time comparisons** for fingerprints/safety numbers and any
   identity-equality checks performed in app code.
7. **Logging discipline.** Guarantee no key material, plaintext, or
   safety-relevant state reaches logs, crash reports, previews, or test output.
8. **Keychain access control.** Consider biometric/passcode gating
   (`SecAccessControl`) for identity-key use.
9. **At-rest storage (Phase 5).** Encryption key derivation, ephemeral-mode
   guarantees, and secure deletion.

### Metadata / traffic analysis (design-level)
10. **Padding & cover traffic** to blunt size/timing analysis.
11. **Advertisement/identifier rotation** to limit device tracking over BLE.

### What an auditor should focus on
- Correctness of the Noise XX state machine and the Double Ratchet (especially
  DH-ratchet steps, skipped-key handling, and AEAD nonce derivation).
- Domain separation of all derived keys.
- The identity ↔ Noise-static binding (item 1) and the trust-establishment UX.
- That every field influencing decryption, trust, routing, or replay is
  authenticated.

---

## Contributor Review Checklist

- Are all fields influencing decryption, trust, routing, or replay authenticated?
- Are all derived keys domain-separated by protocol context?
- Is any private material logged, serialized, previewed, or emitted in tests?
- Does the change preserve identity continuity and keep resets explicit?
- Are replay, out-of-order, and dropped-message paths tested?
- Does the UI avoid implying a peer is verified before safety-number comparison?
- Does transport/mesh code treat all Bluetooth metadata as public?
- Does new crypto compose CryptoKit primitives rather than reimplement them?
```
