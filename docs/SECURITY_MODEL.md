# Pigeon — Security Model

> **Status: pre-release prototype. NOT independently audited.**
> This document describes the design and current implementation of Pigeon's
> security. It is a working model for implementation and review, **not** an
> audit report, and Pigeon should not yet be relied on against a real
> adversary. See [Audit Readiness](#audit-readiness--pre-audit-notes).

Pigeon is an open-source messenger built for **extreme privacy and security**
across offline-capable local transports and federated server transports.
In-range, messages can travel end-to-end encrypted over a local **Bluetooth Low
Energy mesh**. For peers who are **out of local range and on different
networks** (e.g. cellular), Pigeon can deliver the same end-to-end ciphertext
over the internet through a **zero-knowledge relay** — a self-hostable mailbox
that stores and forwards ciphertext addressed by public key and **never sees
plaintext**.

Local mesh and federated relay delivery are transport options, not different
trust models. Relays learn connection metadata (endpoints, timing,
who-exchanges-with-whom) but no content, and they are never trusted for
confidentiality, authentication, or integrity. Identity is a key pair on your
device; there is nothing to register with a central Pigeon service.

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
- **Transport flexibility without weakening trust.** Local and relay transports
  carry the same end-to-end-protected bytes. Relays are blind ciphertext
  mailboxes and are never trusted for confidentiality, authentication, or
  integrity, all of which are enforced end-to-end below the transport.
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
│ Transport (`Transport` protocol)  pluggable pipes│
│   • BLE: CoreBluetooth central+peripheral · GATT │
│   • Relay (opt-in): blind ciphertext mailbox     │
│   moves opaque ciphertext only · runs concurrently│
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

> **Identity ↔ Noise-static binding (implemented):** the Noise handshake uses an
> **X25519 static** key while the *identity* is **Ed25519**. These are bound via
> `IdentityBundle` — the X25519 static key is signed by the Ed25519 identity, and
> the signed bundle is the QR payload. At session establishment, the handshake's
> `remoteStaticKey` is checked against the verified bundle, so comparing safety
> numbers authenticates the encrypted channel. (Still in scope for the overall
> audit.) See [Audit Readiness](#audit-readiness--pre-audit-notes).

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
- **Fit:** libsignal is coupled to Signal's server-mediated model (registration,
  prekey servers, sealed sender) — a poor match for Pigeon's transport-flexible
  mesh and federated relay architecture.
- **Auditability:** a focused Swift package over CryptoKit is something
  contributors can actually read, unlike a vendored Rust/C blob.
- **Risk boundary:** we implement *protocol composition*, not primitives, which
  is a far smaller and more checkable surface than implementing curve math.
  This does **not** remove the need for an external audit (§Audit Readiness).
- **License:** the app and the packages it links (`PigeonCrypto`, `PigeonMesh`)
  are **MIT** — permissive and App Store–compatible. The standalone **`relay`
  server is AGPL-3.0-only** (it isn't linked into the app, so AGPL's network
  copyleft applies only to relay operators). libsignal is AGPL-3.0; pulling it
  into the app would force the app to AGPL and reintroduce the App Store conflict
  (VLC precedent) — so license is now a reason the clean-room packages stay MIT,
  alongside fit, auditability, and the risk boundary above.

---

## 6. Transport & Mesh

The transport layer is a pluggable `Transport` abstraction: a "dumb pipe" that
moves **opaque ciphertext** between peers and knows nothing about encryption,
identity, or routing. Encryption (§5) and the mesh sit above it, so every
transport carries the same end-to-end-protected bytes and any number can run at
once.

- **BLE transport:** CoreBluetooth, each device acting as both central and
  peripheral; a custom GATT service; message chunking/reassembly to fit BLE MTUs;
  framing. Offline-capable local delivery with no server involved.
- **Mesh:** packet format with TTL, duplicate-suppression (seen-cache), and
  **store-and-forward** relaying so messages hop toward out-of-range peers.
  Relays handle ciphertext only.
- **Session establishment is interactive for now:** two contacts must be in mesh
  contact to run the Noise handshake; thereafter ratchet messages relay
  asynchronously. **Async first contact** (X3DH-style prekeys shared through QR,
  mesh gossip, or relays) is a planned later enhancement, with its own
  replay/exhaustion considerations.

### 6.1 Relay transport (remote delivery) — opt-in

Two devices that are out of Bluetooth/local-Wi-Fi range and on different networks
(e.g. both on cellular) **cannot connect directly**: behind NAT/CGNAT a phone can
dial out but cannot be dialed in, so there is no peer-to-peer path. Reaching them
requires a mutually-reachable rendezvous — a **server**. This is a property of
the internet, not a Pigeon limitation. Pigeon treats that rendezvous as an
untrusted federated transport, not as part of the security boundary.

Pigeon keeps the trust cost minimal:

- The relay is a **zero-knowledge mailbox**: clients connect *outbound* (e.g.
  WebSocket), upload ciphertext **addressed by recipient public key**, and the
  relay stores-and-forwards it. It is just another `Transport` carrying the same
  ratchet ciphertext — **it cannot read messages**, and confidentiality,
  authentication, integrity, forward secrecy, and the safety-number trust check
  are all unchanged and enforced end-to-end below it.
- It is **opt-in** and **self-hostable** (run your own; a homelab/Kubernetes or
  small VPS deployment is sufficient). The design is **federated** — each user
  advertises the relay(s) they can be reached at in their QR contact card, and a
  sender deposits only on *that recipient's* relays. Independent relays, chosen
  per user, like email or Nostr relays — no single central party, no
  server-to-server protocol.
- **Relay URLs in the card are unauthenticated delivery hints**, not signed
  identity: only the 128-byte bundle is signed. They are exchanged over the
  in-person QR channel, and a wrong/hostile relay can only observe that
  ciphertext for a key exists, or drop it (a DoS) — it cannot read content or
  affect trust, which live entirely in the bundle and the ratchet. Reading a
  mailbox still requires proving ownership of its key (a signed challenge), so a
  relay cannot hand your mailbox to anyone else.
- **What the relay can see is metadata**, not content: client IP/endpoints,
  timing, message sizes, and that *some* sender is delivering to recipient key X.
  Mitigations (sealed-sender addressing, padding, and routing over **Tor** to hide
  IPs) are planned, not yet implemented.

> A relay is **untrusted infrastructure**. Compromising or operating one yields
> metadata and the ability to drop/delay/replay ciphertext (a denial-of-service
> and traffic-analysis position), but **never plaintext, impersonation, or a
> trusted session** — those are gated by the identity↔Noise-static binding and
> the AEAD/ratchet authentication, which the relay cannot forge.

---

## 7. Attacker Model

**Assume an attacker can:**
- Observe, record, replay, delay, drop, and reorder Bluetooth traffic.
- Operate or compromise relay devices in the mesh.
- **Operate or compromise an internet relay server** (if the user enables relay
  delivery): observe connection metadata — client IP/endpoints, timing, sizes,
  and that a sender is delivering to recipient key X — and drop, delay, or replay
  ciphertext. The relay **cannot** read content, impersonate a peer, or forge a
  trusted session.
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
- **Relay metadata (if enabled).** An internet relay sees endpoints, timing,
  sizes, and sender→recipient-key mappings — never content. Sealed-sender,
  padding, and Tor routing to blunt this are planned, not implemented. Local
  transports avoid relay metadata; relay transports provide remote reach.
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
1. ~~**Bind Noise static ↔ Ed25519 identity.**~~ ✅ **Implemented.** `IdentityBundle`
   carries the X25519 static key signed by the Ed25519 identity; the QR payload
   is the signed bundle; `SessionManager` rejects any established session whose
   handshake `remoteStaticKey` does not equal the verified bundle's static key.
   (Still subject to overall audit, but the gap is closed.)
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
12. **Relay metadata minimization.** Sealed-sender addressing (so the relay
    cannot see the sender), uniform padding, and optional Tor routing to hide
    client IPs.

### Relay transport (new surface; only when remote delivery is enabled)
13. **Relay stays zero-knowledge.** Verify the relay only ever handles opaque
    ciphertext addressed by recipient key, with no field it can use to read,
    link, or tamper with content beyond drop/delay/replay.
14. **Replay/freshness across the relay.** Store-and-forward over a relay must
    not widen the handshake/message replay surface (ties to item 3).
15. **Relay abuse & retention.** Authentication-free mailboxes invite spam/DoS
    and unbounded storage; define rate-limiting, per-recipient quotas, and
    ciphertext age expiry. No plaintext, keys, or linkable logs server-side.
16. **Transport authenticity.** A malicious relay must not be able to forge
    "delivered" state or inject packets that bypass mesh dedup/auth.

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
