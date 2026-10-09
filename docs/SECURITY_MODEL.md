# Pigeon — Security Model

> **Status: pre-release prototype. NOT independently audited.**
> This document describes the design and current implementation of Pigeon's
> security. It is a working model for implementation and review, **not** an
> audit report, and Pigeon should not yet be relied on against a real
> adversary. See [Audit Readiness](SECURITY_REVIEW.md#audit-readiness-pre-audit-notes).

Pigeon is a source-available messenger with open-source protocol, mesh, and relay
packages, built for **extreme privacy and security**
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
- Multi-device identity sync.

---

## 3. Architecture Overview

> **Visual walkthrough.** For an illustrated, plain-language version of the flows
> below — identity exchange, the handshake, the ratchet, and each transport —
> see [How Pigeon Works](HOW_IT_WORKS.md). Its accessible SVG flow diagrams show
> what each party's keys do and what a relay can and cannot see.

```
┌──────────────────────────────────────────────┐
│ App (SwiftUI, iOS target; iPad-on-Mac capable) │
│  onboarding · contacts/QR verify · chat        │
├──────────────────────────────────────────────┤
│ Storage  encrypted-at-rest + ephemeral mode     │
├──────────────────────────────────────────────┤
│ Mesh  packet format · TTL · dedup ·             │
│                 store-and-forward relay          │
├──────────────────────────────────────────────┤
│ Transport (`Transport` protocol)  pluggable pipes│
│   • BLE: CoreBluetooth central+peripheral · GATT │
│   • Relay (default on): blind ciphertext mailbox │
│   moves opaque ciphertext only · runs concurrently│
├──────────────────────────────────────────────┤
│ pigeon-core (Rust, via PigeonFFI XCFramework)    │
│   Olm session establishment + Double Ratchet     │
│   (vodozemac) · identity binding on top           │
├──────────────────────────────────────────────┤
│ Identity (app)  Ed25519 key in Keychain,         │
│                 fingerprint, safety number       │
└──────────────────────────────────────────────┘
```

End-to-end encryption is performed by the two conversation endpoints (the Olm
sessions in `pigeon-core`). The mesh layer relays opaque ciphertext;
**relays learn routing/metadata but never plaintext.**

---

## 4. Identity & Trust

- Each device generates a long-term **Ed25519** identity key pair on first
  launch (`Curve25519.Signing` via CryptoKit).
- The private key is stored in the **Keychain**, always `…ThisDeviceOnly`:
  device-only, excluded from iCloud and backups. Its lock-state accessibility
  follows the **background-delivery** preference (see below).
- **Background delivery (opt-out, on by default).** To notify the user of new
  messages while the device is locked, a background relaunch must read the
  identity key to authenticate to the relay. When background delivery is
  enabled, the identity key uses
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (readable while locked after
  the first unlock since boot); when disabled, they use the stricter
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (readable only while unlocked).
  The trade-off is a wider window for forensic key extraction from a powered-on,
  already-unlocked device — a hard, narrow attack vector — versus background
  notifications. The message itself is never decrypted while locked: inbound
  envelopes are held in memory (and retained on the relay, unacked) and processed
  only after the vault is unlocked. Plaintext and history stay behind the
  biometric-gated vault regardless of this setting. Locked startup is
  load-existing-only: it can never generate or replace an identity before
  protected data becomes available.
- MLS signing, group-capability, and group-recovery private keys always use
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. They are migrated to that
  class when loaded. A process that loaded them before screen lock may retain
  them in memory for durable running-process delivery; a cold locked launch
  cannot load them or mutate group cryptographic state.
- **Secure Enclave is deliberately not used**: it supports only P-256, which is
  incompatible with the X25519/Ed25519 stack the protocols require.
- The public key's **SHA-256 fingerprint** is the device's address/handle.
- Public identities are exchanged **in person via QR code** or remotely as a
  `https://pigeonwire.app/contact` link containing the same public ContactCard. A remotely
  imported card is explicitly marked **not verified in person**. From a pair of
  public keys we derive a **60-digit safety number** (order-independent, 5200
  rounds of domain-separated iterated hashing under the versioned context
  `Pigeon.SafetyNumber.v1`) that users compare over a trusted channel to detect
  MITM. Bumping that context version changes every safety number, so contacts
  must re-compare in person.
- **Identity reset** generates a fresh key, irreversibly invalidating all
  existing trust relationships. This is, and must remain, user-visible.
- A reinstall that loses the app container but retains the Keychain identity
  stops at a recovery screen. Starting fresh requires device-owner
  authentication, erases the old store family and scoped keys, and rotates both
  the root identity and vault key. A checkpoint continuity marker also prevents
  an existing installation from silently recreating missing core state.
- A phone-to-phone move requires the unlocked old phone and fresh owner
  authentication. Both phones compare a 12-digit code derived from an ephemeral
  P-256 key agreement. Directional AES-GCM frames carry the root seed, scoped
  signing seeds, the live core checkpoint, contacts, and group metadata over
  nearby transport. Saved direct and group message history is excluded. The
  receiving phone stages identity seeds in ThisDeviceOnly Keychain slots and
  the checkpoint under a random staged vault key. It activates only after
  recording a root-signed retirement receipt sent after the old phone's
  Clean Slate completes. An unretired staged move can be discarded only after
  an explicit warning and device-owner authentication. An offline, lost old
  phone cannot authorize recovery of that identity. If the old phone relaunches
  with a prepared move record, its session remains frozen before any core
  transaction or link resubscription; a corrupt record blocks restore. The
  record is removed before the old session may resume after cancellation.

> **Identity ↔ Olm-key binding:** Olm authenticates a session by its
> **Curve25519** identity key, while Pigeon's *identity* is **Ed25519**. These are
> bound via `IdentityBundle` — the Curve25519 identity key is signed by the
> Ed25519 identity, and the signed bundle is carried by the QR/contact-link
> payload. At establishment, the session's reported peer identity is checked
> against the imported bundle, so comparing safety numbers authenticates the
> encrypted channel. (Still in scope for the overall audit.) See
> [Audit Readiness](SECURITY_REVIEW.md#audit-readiness-pre-audit-notes).

---

## 5. Cryptographic Design

The pairwise messaging protocol is **Olm**, provided by the audited
[`vodozemac`](https://github.com/matrix-org/vodozemac) Rust crate and reached
from the app through the `pigeon-core` / `PigeonFFI` XCFramework. Pigeon does
**not** implement the ratchet, session establishment, or any primitive
algorithm; it adds exactly one piece of protocol trust on top of Olm — the
identity binding — and otherwise drives Olm's account/session API. App-side
identity signing and at-rest storage use Apple **CryptoKit**.

### 5.1 Primitives
Olm's cipher suite, as implemented by `vodozemac`:
- **X25519 (Curve25519)** ECDH for session establishment and the Double Ratchet's
  DH steps.
- **HKDF-SHA256** for root/chain key derivation.
- **HMAC-SHA256** for chain-key advancement and message authentication.
- **AES-256-CBC** for message encryption (Encrypt-then-MAC with HMAC-SHA256).

App-side, via CryptoKit:
- **Ed25519** signatures for the identity binding and relay-challenge auth.
- **AES-256-GCM** for at-rest storage (`SecretBox`).
- **SHA-256 / SHA-512** for fingerprints and safety-number derivation.

### 5.2 Identity binding (`pigeon-core` `identity.rs`)
Olm authenticates sessions by **Curve25519** keys, but does not by itself tie a
peer's Curve25519 identity key to a stable, human-verifiable identity. Pigeon's
root of trust is a long-term **Ed25519** identity key (the safety-number root).
That identity key **signs Olm's Curve25519 identity key**, producing the
`IdentityBundle` carried in the QR card. Verifying a peer's safety number
therefore authenticates the whole channel. The Ed25519 identity is independent of
the Olm account, so re-pickling or rotating Olm keys never churns safety numbers.

### 5.3 Sessions & the Double Ratchet (Olm)
- Each device owns one Olm **account** (its Curve25519 identity key, a pool of
  one-time keys, and a fallback key). Each conversation is one Olm **session**.
- The session provides **forward secrecy**, **post-compromise security**, and
  **out-of-order / skipped-message** tolerance — all from vodozemac's Double
  Ratchet, essential over a lossy BLE mesh.
- `pigeon-core`'s `Session` wraps the Olm session only to enforce the identity
  binding at establishment and to report the peer's verified Ed25519 key for the
  safety-number check; after that, encrypt/decrypt are straight Olm.

### 5.4 Wire format
All bundles and messages use the shared **`pigeon.wire.v1`** Protocol Buffer
schemas under `proto/pigeon/wire/v1/`, encoded identically by the
Rust core and the Swift app. An Olm message crosses the wire as
`pigeon.wire.v1.OlmMessage` (its type tag + ciphertext); first contact crosses as
`pigeon.wire.v1.Initiation` (the initiator's identity bundle + the first Olm
pre-key message).

### 5.5 Why Olm/vodozemac
- **Audited ratchet and primitives.** `vodozemac` is a focused, audited Rust
  implementation of Olm/Megolm, so the ratchet and session establishment are not
  Pigeon's own code to get right. This does **not** remove the need for an
  external audit of Pigeon's *use* of it (§Audit Readiness).
- **Cross-platform core.** A Rust core can back future non-Apple clients without
  re-implementing the protocol per platform.
- **Async-first.** Olm establishes from published prekeys without an interactive
  round trip — a natural fit for a mesh/relay network where peers are often
  offline (§5.7).
- **License:** the reusable messaging-core, mesh, and relay packages should
  remain open and copyleft, not source-visible-but-closable.
  **`pigeon-core`, `pigeon-ffi`, `pigeon-mesh`, and `pigeon-relay` are
  AGPL-3.0-only**, so modified versions offered to users, including over a
  network, must keep their source available. The iOS app and app-specific code
  are source-available for transparency, local development, and security review,
  but are not open source; commercial use, redistribution as an app, and
  App Store/TestFlight publication require permission from the Pigeon
  maintainers.

### 5.6 Constant-time comparisons & key handling

Secret comparisons happen inside vetted code. Olm tag verification and the
ratchet live in `vodozemac`; Ed25519 signature checks (the identity binding and
prekey signatures) run in `ed25519-dalek` (Rust core) and CryptoKit (app). The
one authentication decision Pigeon makes in its own code — that a session's
reported peer identity equals the verified contact's identity key — is a
comparison of **public** Ed25519 keys, so it is defense-in-depth rather than a
confidentiality-critical secret comparison.

Secret key material (the Olm account, session state, message and chain keys) is
owned and zeroized by `vodozemac`. Pigeon's own secret handling is limited to the
32-byte Ed25519 identity seed (Keychain) and the sealed Olm account pickle
(vault); it does not keep ratchet state in long-lived app buffers.

### 5.7 Async first contact — Olm prekeys

Olm is **async-first**: a sender can open a session and send a first message to a
peer who is offline, using prekeys the recipient published ahead of time (in its
QR card, or via mesh/relay). There is no interactive handshake to complete; the
normal Double Ratchet (§5.3) takes over once the peer replies.

**Reuse of existing trust.** No new root of trust is introduced. The recipient's
identity bundle (§5.2) is reused verbatim, and every published prekey is signed
by the same Ed25519 identity, so verifying a peer's safety number authenticates
first contact too. The recipient publishes:
- a **signed fallback prekey** — a long-lived Curve25519 prekey, signed by the
  identity key, always available; and
- a pool of **one-time prekeys (OPKs)** — likewise signed, each consumed once.

`pigeon-core` verifies the identity binding *and* the prekey signature before any
session is opened, so a relay or mesh forwarder cannot substitute a key.

**Establishment.** The initiator runs Olm's outbound session against the
recipient's identity + prekey, encrypts the first plaintext into an Olm **pre-key
message**, and transmits a single `pigeon.wire.v1.Initiation` (its identity
bundle + that pre-key message). The recipient creates the matching inbound
session from the pre-key message, recovering the first plaintext; consuming the
named one-time key is the replay defense.

**Tradeoffs (deliberate, inherent to Olm).**
- **Replay.** A one-time prekey makes first contact single-use: once consumed the
  recipient cannot re-derive the same inbound session, so a replayed initiation
  fails. When the OPK pool is exhausted Olm falls back to the **fallback key**,
  which Olm deliberately permits reusing. Pigeon therefore persists a SHA-256
  digest of every accepted initiation per contact and refuses any previously
  accepted payload before it can replace the current session. A recording made
  before this ledger first existed is outside the ledger; fallback-key rotation
  bounds that migration window. Pigeon replenishes OPKs and rotates the fallback
  key when next online. Digests survive contact removal and are capped at 256 per
  identity; after the cap, further fresh initiations fail closed instead of
  allowing unbounded encrypted-store growth. A future full identity rotation
  clears the ledger because recordings addressed to the old identity are no
  longer valid.
- **Exhaustion / availability.** Olm uses the fallback key rather than refusing
  first contact when OPKs run out — availability chosen over denying delivery.
- **Weaker forward secrecy at rest until the first reply.** Until the recipient
  replies and the ratchet performs its first DH step, secrecy rests on the
  long-lived fallback key (or the consumed OPK). This is inherent to async setup
  and is why fallback rotation + OPK consumption matter.
- **No forward secrecy for the prekey-publication metadata** itself; prekeys are
  public by construction.

### 5.8 Group chats — MLS

Group chats use **MLS 1.0 (RFC 9420)** through OpenMLS 0.9 in `pigeon-core`, with
the `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ciphersuite. MLS credentials
are bound to Pigeon's long-term Ed25519 root identity with a domain-separated
signature. The OpenMLS signer delegates back to the platform identity boundary;
private identity and MLS state do not cross into Swift or `pigeon-ffi`.

The core persists the OpenMLS storage checkpoint, authenticated group policy,
pending mutation, replay ledgers, application events, and outbound effects as one
transaction. Ciphertext or host-visible events are not released before that
checkpoint commits. The app then persists replayable events in its encrypted
history before acknowledging them to the core. This ordering prevents a crash
from reusing an MLS state or losing the sender's local message projection.

Membership is mutable and capped at 128. An owner can create a group alone and
add members later. The immutable
owner identity is always an admin and cannot be removed or demoted. Authenticated
policy commits enforce admin membership changes, owner-only name/relay/mesh
changes, member leave, and owner dissolve. Dissolution is terminal: after the
dissolution commit is appended, the owner revokes the group at the relay, which
immediately refuses further appends, coordinator submissions, and capability
changes but keeps read access and the signed coordinator log for one group TTL
so offline members can still receive the terminal commit. Each roster mutation advances the MLS
epoch: joiners receive no pre-join message keys, and former members receive no
post-removal epoch keys.

Each group selects one relay deployment. Its group endpoint provides both the
opaque ciphertext mailbox and a coordinator that serializes concurrent MLS
commits. Coordinator receipts are Ed25519-signed and bound into the group policy.
The coordinator is untrusted for confidentiality and authorization: clients
validate receipts, MLS commits, and policy transitions. A malicious coordinator
can delay, drop, replay, or withhold progress, but should not be able to forge a
valid transition or decrypt content. Pairwise Olm control messages carry join
requests, join material, and welcomes before a new member can authenticate to
the group mailbox. They also carry a member's signed leave proposal to current
admins, allowing any online admin to commit the leave without owner availability.
The core rejects signed addressed controls received outside their
authenticated pairwise wrapper and withholds pending controls until a
pairwise contact can carry them. Normal group messages are encrypted once
with MLS, not fanned out.

Clients persist a coordinator receipt sequence independently from the group
message cursor. A wake drains both bounded streams until empty. A correctly
signed receipt whose opaque candidate fails MLS or policy validation is consumed
transactionally and emits a security-warning event; this prevents a malformed
entry from wedging every later sequence without treating it as valid group state.

Group delivery uses the selected relay. The app does not send or accept group
messages over the local mesh; pairwise chats can still use local transports.

Group delivery receipts are MLS application messages, so only members can read
which messages they acknowledge. A member queues receipts durably and sends them
as one batched acknowledgement per group after an interval that grows with group
size (2 seconds, or half a second per member, whichever is longer), or as soon
as 128 are queued. The relay sees each batch as one more opaque group entry from
that member's capability; batching limits both mailbox growth and how precisely
the relay can time when each member read the group.

Every roster entry authenticates that member's Pigeon root identity, MLS
signature key, relay-capability key, and recovery key in the MLS group-context
policy. Membership commits replace the relay's complete capability set rather
than editing individual grants. The app does not surface the membership event
until the selected relay confirms that canonical replacement, so a removed
member's old read/append capability is revoked before the removal is presented
as complete.

If the selected coordinator is unavailable, any current admin may propose a
replacement relay/coordinator binding. The proposal commits to the exact group,
MLS epoch, policy revision and hash, roster hash, last coordinator receipt, and
the replacement capability-set hash. When delegated admins exist, a strict
majority of those non-owner admins must sign with their policy-bound recovery
keys; the permanent owner is the sole endorser only when no delegated admin
exists. Proposals and endorsements travel as application data inside the
existing MLS group over its current group mailbox. Recovery can proceed without
the owner while that relay remains reachable; a relay outage blocks proposal
delivery until connectivity returns. The result is an ordinary MLS epoch
transition, and stale, replayed, minority, or removed-member certificates fail
closed. Recovery restores coordination authority, not connectivity.

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
- **Session establishment is async-first:** Olm establishes a session from the
  recipient's published prekeys (signed prekey + a one-time prekey carried in the
  QR card/contact link or shared over mesh/relay), so the first encrypted message
  can be sent without the recipient being online. There is no interactive handshake. The
  prekey path has its own replay/exhaustion considerations, handled inside Olm's
  one-time-key accounting (see §5.7).

### 6.1 Relay transport (remote delivery) — on by default, user-controllable

![Federated relay flow](diagrams/pigeon_04_relay.svg)

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
- It is **on by default, user-controllable**, and **self-hostable** (run your own; a homelab/Kubernetes or
  small VPS deployment is sufficient). The design is **federated** — each user
  advertises the relay(s) they can be reached at in their ContactCard, and a
  sender deposits only on *that recipient's* relays. Independent relays, chosen
  per user, like email or Nostr relays — no single central party, no
  server-to-server protocol.
- **Relay URLs in the card are signed delivery hints.** The identity bundle signs
  the identity ↔ Olm Curve25519 binding; the relay URL list is signed separately
  by the same Ed25519 identity key so cards remain parseable and `pigeon-core`
  stays identity-agnostic about transport. A scanner only honors relay URLs if
  that URL signature verifies. A wrong or malicious relay can observe that
  ciphertext for a key exists, or drop it (a DoS), but it cannot read content or
  affect trust, which live in the signed bundle and the ratchet. Reading a
  mailbox still requires proving ownership of its key (a signed challenge), so a
  relay cannot hand your mailbox to anyone else.
- **What the relay can see is metadata**, not content: client IP/endpoints,
  timing, message sizes, and that *some* sender is delivering to recipient key X.
  Mitigations (sealed-sender addressing, padding, and routing over **Tor** to hide
  IPs) are planned, not yet implemented.
- Pairwise queues are transient and memory-only. Group authorization,
  ciphertext, cursors/tombstones, and signed coordinator receipt chains are
  committed to local SQLite before acknowledgement so a restart cannot forget a
  revocation or reuse a coordinator sequence. The durable database contains no
  plaintext or private client keys, but it does retain group-level metadata and
  opaque content until TTL/cursor reclamation. Startup fails closed if the
  configured coordinator signing key does not match the stored log identity.
- **Relay compatibility is negotiated before mailbox access.** The app and relay
  exchange inclusive minimum/maximum relay-protocol versions before publish,
  subscribe, authentication, acknowledgement, or push registration. Both select
  the highest overlapping version. Missing, malformed, or disjoint ranges fail
  closed; an incompatible relay is excluded from delivery, reachability, and new
  contact cards, while remaining visible in settings for diagnosis. This version
  is independent of the app and relay SemVer. A malicious relay can lie about its
  range, so negotiation prevents accidental incompatibility but does not add
  trust or weaken end-to-end authentication.

> A relay is **untrusted infrastructure**. Compromising or operating one yields
> metadata and the ability to drop/delay/replay ciphertext (a denial-of-service
> and traffic-analysis position), but **never plaintext, impersonation, or a
> trusted session** — those are gated by the identity ↔ Olm Curve25519 binding
> and the Olm message authentication, which the relay cannot forge.

#### Push wake-up (APNs) — official relay only, on by default

Relay delivery is otherwise WebSocket-pull only: to receive, the app must be
running and holding an authenticated subscription to its mailbox. iOS suspends or
terminates backgrounded apps, so a message can sit in the mailbox unseen until the
user reopens Pigeon. APNs is the only Apple-sanctioned way to wake a suspended or
terminated app, and an APNs push to the Pigeon bundle id can only be signed by the
holder of the app's `.p8` key — the app publisher. So push **cannot be federated**:
the **official** Pigeon relay additionally runs a thin APNs gateway; self-hosted
and third-party relays leave it unconfigured and never push (best-effort
background reception, exactly as before).

It is **on by default but user-controllable** (Relays → Push wake-ups turns it
off, falling back to best-effort background reception). When on, the client
registers its APNs device
token with its official relay over the *existing* mailbox-ownership handshake
(`Subscribe → Challenge → Auth`), so a token can only ever be bound to a mailbox
by that mailbox's key holder — no new trust path. When ciphertext is deposited for
a mailbox with a registered token, the gateway sends a **content-free** visible
alert ("New message / Open Pigeon to read your message") — no sender, content, or
count. The push only wakes the app; it then drains the mailbox and decrypts on
unlock through the unchanged locked-receive pipeline. **No message content ever
traverses Apple.**

The cost is **metadata, not confidentiality**. This centralizes the *wake signal*:
the official gateway learns `device token ↔ "this mailbox has mail at time T"`, and
Apple sees push-delivery metadata — more than the blind relay alone. Pushes are
coalesced per mailbox to blunt deposit-driven timing leakage. Group chats extend
the same wake signal to group readers: the gateway learns `device token ↔ "this
group has a new entry, coordinator receipt, or dissolution at time T"`, which
also reveals which registered tokens read the same group. This is a deliberate,
documented exception to the project's "no new network services beyond the relay"
rule and to the relay's "learns only public keys" property (now also a device
token, on the official deployment only). A future Notification Service Extension
for richer (decrypted) notifications would require loosening the biometric vault
and is explicitly out of scope.

---
Continue with the [attacker model, known limitations, and audit readiness](SECURITY_REVIEW.md).
