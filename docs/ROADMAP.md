# Pigeon — Roadmap

Pigeon is an open-source messenger built for **extreme privacy and security**
across offline-capable local transports and federated server transports.
Messages can travel end-to-end encrypted over a **Bluetooth Low Energy mesh**,
or over an **optional zero-knowledge relay** for peers out of local range on
different networks. The relay carries the same ciphertext over the internet and
never sees plaintext.
See [SECURITY_MODEL.md](SECURITY_MODEL.md) for the security design (incl. §6 on
why remote delivery needs a relay) and audit-readiness tracking.

This is one timeline: what's shipped, what's in progress, and where we're headed.
Status: `✅ done · 🟡 in progress · ⬜ planned · 🔭 horizon`.

## Locked architecture decisions

- **Platforms:** iOS-only target. On Apple Silicon Macs it runs unmodified via
  "Designed for iPad" (iOS apps on Mac) — no separate macOS/Catalyst target.
  visionOS dropped. Compile-check on the iOS Simulator.
- **Topology:** transport-flexible encrypted mesh — BLE today, relays in
  progress, and other links later. Every transport forwards ciphertext it cannot
  read.
- **Remote delivery:** opt-in, self-hostable **zero-knowledge relay** (blind
  ciphertext mailbox; federation-friendly) for peers out of local range. Relays
  are a first-class transport option but are never trusted for confidentiality,
  authentication, or integrity.
- **Crypto:** Signal-grade end-to-end encryption via **Olm** (the audited
  `vodozemac` crate) in the Rust `pigeon-core`, with Pigeon's own long-term
  Ed25519 identity binding layered on top. Migrated (#79–#83) from the original
  clean-room Swift `PigeonCrypto` (Noise XX + Double Ratchet over CryptoKit),
  which has been removed. libsignal was rejected (AGPL/App-Store conflict,
  server-coupled design); a Rust core keeps the protocol portable across future
  clients and reachable from the app through a UniFFI bridge.
- **Storage:** encrypted-at-rest (key tied to biometrics/passcode) + per-chat
  ephemeral (no-persistence) mode.
- **Identity:** on-device Curve25519 keypair (no accounts/phone numbers); public
  key fingerprint is the address; trust via in-person QR exchange + safety number.
- **Mesh:** the transport layer (framing, dedup/TTL flood routing, BLE
  fragmentation, session envelope) is the shared Rust `pigeon-mesh` crate,
  reached from the app through the same FFI bridge as `pigeon-core`. It carries
  opaque ciphertext and holds no crypto, and keeps tiny fixed-width wire headers
  (not protobuf) so it fits small BLE MTUs and every client shares one format.

## Module layout

- `pigeon-core/` — Rust crate (AGPL): the pairwise messaging core over Olm/
  `vodozemac` — identity binding, account/prekeys, sessions, the protobuf wire
  format. Reached from the app through the UniFFI bridge.
- `pigeon-ffi/` — UniFFI crate: builds the XCFramework and generates the Swift
  bindings vended by the `PigeonFFI` package (the app's crypto/mesh facade).
- `pigeon-mesh/` — Rust crate: Fragmentation, MeshPacket (dedup/TTL/relay),
  SessionEnvelope (dependency-free, surfaced through the FFI).
- `pigeon-relay/` — Rust (axum/tokio) zero-knowledge relay; ships as a Docker image.
- `Pigeon/` (app) — Identity (Keychain), CoreBluetooth transport, MeshService,
  SessionManager, encrypted storage, notifications, and SwiftUI. Links `PigeonFFI`.

---

## Timeline

### ✅ Shipped

- **Identity** — Curve25519 identity key in the Keychain, fingerprint, safety number.
- **Crypto core (`pigeon-core`, Rust)** — Olm via the audited `vodozemac` crate:
  Double Ratchet, async-first session establishment, and Pigeon's identity binding
  (a long-term Ed25519 key signs Olm's Curve25519 identity key). Reached from the
  app through the UniFFI bridge (`pigeon-ffi` → `PigeonFFI`). Behavioural tests in
  `pigeon-core/tests/`.
- **BLE transport** — dual-role CoreBluetooth, GATT, fragmentation/reassembly sized
  from the negotiated ATT MTU per connection, auto-reconnect; verified on two devices.
- **End-to-end encryption over the mesh** — per-contact Olm sessions, deterministic
  initiator/responder roles, the identity-binding check, encrypted chat.
- **Async first contact (Olm prekeys)** — message a peer who isn't currently
  reachable: signed + one-time prekeys travel in the QR card, OPK is deleted on use,
  and the signed prekey rotates on a schedule (Olm keeps the previous one valid for
  one interval). Includes the "added remotely / not verified in person" trust UX.
- **Mesh** — packet dedup (seen-cache), flood relay with TTL, and a persisted
  per-contact **store-and-forward** queue with delivery acknowledgements (messages
  survive disconnects, lost packets, and restarts) plus a retention policy that
  retires an unacked message after a long horizon instead of resending forever.
- **Delivery confidence** — an honest **Sent → Delivered** status under each
  outbound message (Delivered only on the recipient's end-to-end ack), with a
  "Not delivered" + resend affordance when a message genuinely couldn't be dispatched.
- **Relay transport (remote delivery)** — opt-in `RelayTransport` + a self-hostable
  zero-knowledge mailbox server (Rust, axum/tokio, Docker→GHCR). Carries the same
  E2E ciphertext to peers out of local range: per-recipient **addressed** delivery
  (no fan-out), **federation** (each peer advertises their relays in the QR card and
  senders deposit only there), send-side store-and-forward, and relay unit tests.
  Two-device validation performed. See [SECURITY_MODEL.md §6.1](SECURITY_MODEL.md).
- **Local Wi-Fi transport** — `LocalWiFiTransport`, a Multipeer Connectivity
  `Transport` running alongside BLE and the relay. A dumb pipe carrying the same
  E2E ciphertext; the mesh dedups across BLE/Wi-Fi/relay. No fragmentation (Multipeer
  gives reliable arbitrarily-sized sessions). Privacy: random per-launch peer name
  (no device name on the wire), no discovery metadata, and `.required` session
  encryption as defence in depth. Open local-link trust model like BLE; a
  deterministic invite tie-break avoids forming two sessions per pair. Foreground-only
  (background reach is the relay's job); needs the local-network/Bonjour Info.plist
  entries. **Wi-Fi Aware** stays a Horizon item (Multipeer already covers same-network).
- **Push wake-up (APNs via the official relay)** — opt-in, content-free push that
  wakes a backgrounded app to drain its mailbox (decrypt still happens on unlock).
  Relay token registration over the authenticated `/ws` handshake, a config-gated
  APNs gateway that fires the content-free alert on deposit (coalesced, 410 token
  eviction), and app-side opt-in. Only the app publisher can hold the APNs key, so
  this can't be federated; self-hosted/third-party relays simply don't push. The
  payload is empty, so **confidentiality is untouched**; it does expose wake metadata
  (device token ↔ "has mail at time T") to the gateway and Apple — a deliberate,
  documented exception to "no new network services beyond the relay."
- **Encrypted storage** — biometric-gated `Vault` key + `EncryptedStore`;
  **per-chat ephemeral mode** (synced to the peer, future-messages-only).
- **Onboarding & UI** — name onboarding, QR identity card (name auto-populates on
  scan; edit + copy-fingerprint), contact verification via safety number, contacts
  book + conversations list (avatars, previews, lock state, swipe-to-delete), chat
  with auto-scroll, rename.
- **Notifications** — in-app foreground banner + local notification (no server).
- **`Transport` abstraction** — BLE, local Wi-Fi, and the relay are each one
  implementation of a `Transport` protocol; `MeshService` runs over any transport
  (and several concurrently, deduping across them).

### 🟡 In progress

- **UI polish** — ongoing refinement of chat/contacts.
- **Security hardening / audit prep** — work toward the audit blockers below:
  traffic-analysis resistance (padding/cover traffic), key zeroization,
  constant-time compares, and logging discipline.

### ⬜ Next

- **Relay metadata minimization** — sealed-sender addressing, padding, optional
  Tor routing so the relay sees as little as possible (audit items 12–16).
- **External security audit** — required before any real-world "secure" claim.

### 🔭 Horizon

**Group chats** (E2E; no central authority for ordering/membership):
- **A1 — Pairwise fan-out:** encrypt to each member over existing sessions, tagged
  with a `groupID`. Reuses everything; O(n) bandwidth; good for small groups.
- **A2 — Sender keys (WhatsApp/Signal model):** each member distributes a sender
  key once; O(1) per message. The practical mid-term target.
- **A3 — MLS (RFC 9420):** TreeKEM, log(n) membership changes; the modern standard
  but a large surface — needs a vetted/auditable implementation. Long-term.
- Cross-cutting: signed membership/roster, causal ordering (Lamport/vector clocks,
  eventual consistency), per-group seen-tracking over the flood mesh.
- *Path:* A1 → A2, defer A3.

**Long-distance / non-Bluetooth transport** (same E2E ciphertext across local or
federated paths):
- **Extend local reach:** ~~Multipeer Connectivity~~ ✅ (shipped); **Wi-Fi Aware**
  (infrastructure-less, longer range) and **LoRa** for km-range off-grid text
  (needs hardware) remain.
- **Delay-tolerant "data mules":** hold ciphertext addressed to a recipient and
  deliver when next encountered; physical movement bridges disconnected clusters.
- **Internet (opt-in), in order of fit:** (1) **federated zero-knowledge relays**
  — dumb, self-hostable mailboxes storing ciphertext only (Nostr-relay-like) —
  *shipped (federated), see above*; (2) **Tor** hidden services for metadata
  privacy (Briar-style); (3) direct P2P (NAT traversal usually needs a TURN relay
  — partial at best).
- Metadata is the main new risk: mitigate with sealed-sender, onion routing,
  padding, cover traffic.
- *Path:* ~~Transport abstraction~~ ✅ → ~~self-hosted relay~~ ✅ →
  ~~federation~~ ✅ → metadata hardening (sealed-sender/Tor) → data mules.

---

## Tracked gaps & audit blockers

Several are audit blockers (see [SECURITY_MODEL.md](SECURITY_MODEL.md) → Audit Readiness).

- **External security audit** — required before any real-world "secure" claim.
  **Audit blocker.** The messaging core is Olm via the audited `vodozemac` crate, but Pigeon's identity binding, wire formats, transports, and storage still need independent review.
- **Re-handshake DoS** — mesh envelopes are unauthenticated, so a spoofed
  `rehandshakeRequest`/handshake can force a session reset (no content breach —
  the binding check holds). *Mitigated:* network-triggered re-handshakes are rate-limited per peer with a cooldown, so a spoofed flood costs at most one teardown per window; user-initiated resets bypass the gate.
- **Connection topology** — two dual-role devices form *two* central↔peripheral
  links per pair, so each message crosses BLE twice. This is an **efficiency**
  issue only: the mesh dedup layer already drops the duplicate, so no duplicate is
  ever delivered to the user. A correct dedup can't be done locally — CoreBluetooth
  exposes the same physical peer as a `CBPeripheral` (central role) and a
  `CBCentral` (peripheral role) under *unrelated* UUIDs, with the MAC hidden, so the
  two roles can't be correlated without an app-level handshake. The safe design
  (when built): advertise a per-process instance id, exchange it over each link
  (advertisement + a small control write so a subscribed central can be attributed),
  then suppress the redundant notify to an instance we already write to — keeping
  *both* links for redundancy and falling back to today's behaviour whenever the
  instance is unknown. Deferred deliberately: it needs on-device BLE verification and
  must not risk the delivery path, and correctness is already covered by dedup.
- **Relay-level store-and-forward** — holding *others'* ciphertext to bridge disconnected clusters (data mules) is future work (see Horizon). The local send-queue's own retention is done (below).
- **Background reception** — a locked background relaunch no longer crashes, and
  with opt-out **background delivery** (on by default) the identity key is
  readable after first unlock, so a relaunched app can authenticate to the relay
  and receive. Inbound envelopes are buffered in memory (and left unacked on the
  relay) and a single content-free notification is posted; they decrypt once the
  user unlocks (the message vault stays biometric-gated — no background
  decryption, deliberately). iOS still *suspends* a backgrounded app, which is why
  the opt-in **push wake-up** (Shipped) exists to nudge it awake to drain its mailbox.

*Resolved:* multi-path duplicate delivery (mesh dedup); identity↔Olm-key binding
(the Ed25519 identity signs Olm's Curve25519 identity key); one-sided-restart
reconnection (auto-reconnect + re-handshake); dropped notifications (reliable notify
queue); re-handshake reset DoS (per-peer rate limit); fixed-size BLE fragments
(now sized from the negotiated ATT MTU); unbounded local send queue (retention/
expiry policy); silent "pending" sends (honest Sent → Delivered status + resend).

## Standing principles

- Security-critical code stays small, dependency-free, and auditable; compose
  CryptoKit primitives rather than reimplement them.
- Be honest in docs about what is and isn't verified — nothing is "secure" until
  audited.
