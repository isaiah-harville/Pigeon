# Pigeon — Roadmap

Pigeon is a fully offline, open-source, privacy/security-first messenger.
Messages travel end-to-end encrypted over a local **Bluetooth Low Energy mesh** —
no servers, no accounts, no internet. See [SECURITY_MODEL.md](SECURITY_MODEL.md)
for the security design and audit-readiness tracking.

This is one timeline: what's shipped, what's in progress, and where we're headed.
Status: `✅ done · 🟡 in progress · ⬜ planned · 🔭 horizon`.

## Locked architecture decisions

- **Platforms:** iOS-only target. On Apple Silicon Macs it runs unmodified via
  "Designed for iPad" (iOS apps on Mac) — no separate macOS/Catalyst target.
  visionOS dropped. Compile-check on the iOS Simulator.
- **Topology:** BLE mesh relay — encrypted store-and-forward; relays forward
  ciphertext they cannot read.
- **Crypto:** Signal-grade — Noise handshake + Double Ratchet — implemented
  clean-room over CryptoKit in the standalone `PigeonCrypto` package (chosen over
  libsignal: AGPL/App-Store conflict, server-coupled design, auditability).
- **Storage:** encrypted-at-rest (key tied to biometrics/passcode) + per-chat
  ephemeral (no-persistence) mode.
- **Identity:** on-device Curve25519 keypair (no accounts/phone numbers); public
  key fingerprint is the address; trust via in-person QR exchange + safety number.

## Module layout

- `PigeonCrypto/` — package: Primitives, DoubleRatchet, NoiseHandshake,
  SecureSession, IdentityBundle, SecretBox (identity-agnostic, CLI-tested).
- `PigeonMesh/` — package: Fragmentation, MeshPacket (dedup/TTL/relay),
  SessionEnvelope (dependency-free, CLI-tested).
- `Pigeon/` (app) — Identity (Keychain), CoreBluetooth transport, MeshService,
  SessionManager, encrypted storage, notifications, and SwiftUI. Links both packages.

---

## Timeline

### ✅ Shipped

- **Identity** — Curve25519 identity key in the Keychain, fingerprint, safety number.
- **Crypto core** — primitives, Double Ratchet, Noise XX, SecureSession,
  IdentityBundle (identity↔static binding), SecretBox; ~40 CLI tests.
- **BLE transport** — dual-role CoreBluetooth, GATT, MTU fragmentation/reassembly,
  auto-reconnect; verified on two devices.
- **End-to-end encryption over the mesh** — per-contact sessions, deterministic
  roles, stop-and-wait handshake, the static-key binding check, encrypted chat.
- **Mesh** — packet dedup (seen-cache), flood relay with TTL, and a persisted
  per-contact **store-and-forward** queue with delivery acknowledgements (messages
  survive disconnects, lost packets, and restarts).
- **Encrypted storage** — biometric-gated `Vault` key + `EncryptedStore`;
  **per-chat ephemeral mode** (synced to the peer, future-messages-only).
- **Onboarding & UI** — name onboarding, QR identity card (name auto-populates on
  scan; edit + copy-fingerprint), contact verification via safety number, contacts
  list (avatars, previews, lock state), chat with auto-scroll, rename.
- **Notifications** — in-app foreground banner + local notification (no server).

### 🟡 In progress

- **CoreBluetooth state restoration** — keep receiving (and notifying) after iOS
  *terminates* the app, not just when backgrounded-alive.
- **UI polish** — ongoing refinement of chat/contacts.

### ⬜ Next

- **Hardening / audit prep (Phase 7)** — clear the audit blockers below;
  traffic-analysis resistance (padding/cover traffic), key zeroization,
  constant-time compares, logging discipline.
- **`Transport` abstraction** — make BLE one implementation of a `Transport`
  protocol so `MeshService` can run over other transports. The key enabler for
  everything in the horizon; cheap to do now, do it before shipping new transports.
- **Async first contact (X3DH-style prekeys)** — message a peer who's offline at
  first contact (prekeys in the QR / gossiped over mesh). Unblocks long-distance
  and offline group messaging. Has prekey-exhaustion/replay tradeoffs.

### 🔭 Horizon

**Group chats** (serverless E2E; no central authority for ordering/membership):
- **A1 — Pairwise fan-out:** encrypt to each member over existing sessions, tagged
  with a `groupID`. Reuses everything; O(n) bandwidth; good for small groups.
- **A2 — Sender keys (WhatsApp/Signal model):** each member distributes a sender
  key once; O(1) per message. The practical mid-term target.
- **A3 — MLS (RFC 9420):** TreeKEM, log(n) membership changes; the modern standard
  but a large surface — needs a vetted/auditable implementation. Long-term.
- Cross-cutting: signed membership/roster, causal ordering (Lamport/vector clocks,
  eventual consistency), per-group seen-tracking over the flood mesh.
- *Path:* A1 → A2, defer A3.

**Long-distance / non-Bluetooth transport** (same E2E ciphertext, servers optional):
- **Extend local reach:** Multipeer Connectivity / Wi-Fi Aware (higher bandwidth,
  still offline); **LoRa** for km-range off-grid text (needs hardware).
- **Delay-tolerant "data mules":** hold ciphertext addressed to a recipient and
  deliver when next encountered; physical movement bridges disconnected clusters.
- **Internet (opt-in), in order of fit:** (1) **federated zero-knowledge relays**
  — dumb, self-hostable mailboxes storing ciphertext only (Nostr-relay-like);
  (2) **Tor** hidden services for metadata privacy (Briar-style); (3) direct P2P
  (NAT traversal usually needs a TURN relay — partial at best).
- Metadata is the main new risk: mitigate with sealed-sender, onion routing,
  padding, cover traffic.
- *Path:* Transport abstraction → data mules → federated relays → Tor.

---

## Tracked gaps & audit blockers

Several are audit blockers (see [SECURITY_MODEL.md](SECURITY_MODEL.md) → Audit Readiness).

- **Official Noise test vectors** — tests prove self-consistency only; add
  byte-level conformance. **Audit blocker.**
- **External security audit** — required before any real-world "secure" claim.
- **Re-handshake DoS** — mesh envelopes are unauthenticated, so a spoofed
  `rehandshakeRequest`/handshake can force a session reset (no content breach —
  the binding check holds). Rate-limit / harden.
- **BLE MTU** — raise the fixed conservative fragment size to the negotiated MTU
  per connection; consider write-without-response for throughput.
- **Connection topology** — dedupe the two-way central/peripheral link per pair.
- **Store-and-forward** — queued messages have no age expiry; relay-level
  store-and-forward (holding *others'* packets) is future work (see data mules).
- **Background reception** — works while backgrounded-alive (bluetooth-central);
  surviving full app termination is the in-progress state-restoration work.
- **Lint/format debt** — SwiftLint/SwiftFormat pre-commit hooks fail; commits use
  `--no-verify` for now. Do a cleanup pass.

*Resolved:* multi-path duplicate delivery (mesh dedup), identity↔Noise-static
binding (IdentityBundle), one-sided-restart reconnection (auto-reconnect +
re-handshake), dropped notifications (reliable notify queue).

## Standing principles

- Security-critical code stays small, dependency-free, and auditable; compose
  CryptoKit primitives rather than reimplement them.
- Commit incrementally; each commit should build.
- Be honest in docs about what is and isn't verified — nothing is "secure" until
  audited.
