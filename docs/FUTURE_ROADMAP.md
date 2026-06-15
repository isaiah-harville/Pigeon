# Pigeon — Future Roadmap

Forward-looking plans **beyond** the current phases in [ROADMAP.md](ROADMAP.md).
Nothing here is scheduled or designed in detail yet; this captures direction,
tradeoffs, and recommendations so we build the near-term phases in a way that
doesn't paint us into a corner. Everything must preserve Pigeon's core values:
**no mandatory servers, no accounts, end-to-end encryption, auditability, and
honesty about what isn't proven.**

A guiding principle for both features below: **the crypto is already
transport- and topology-agnostic.** `SecureSession` (Noise + Double Ratchet),
`MeshPacket`, and `SessionEnvelope` don't care whether bytes move over Bluetooth
or the internet, or whether there are 2 parties or 20. Most of this work is new
layers above the existing ones, not rewrites.

---

## A. Group Chats

End-to-end-encrypted group messaging **with no server to hold group state** is
genuinely hard: there's no central authority to order messages or arbitrate
membership. We'll phase it.

### A1. Pairwise fan-out (smallest first step)
Send a group message by encrypting it separately to each member over the
existing per-contact `SecureSession`, tagged with a shared `groupID`.

- **Pros:** reuses everything we have; no new cryptography; inherits forward
  secrecy / post-compromise security per pairwise channel.
- **Cons:** O(n) bandwidth per message (bad over BLE for large groups); no
  group-level membership consistency.
- **Good for:** small groups (≤ ~8), proves the group UX and addressing.

### A2. Sender Keys (the WhatsApp/Signal-group model)
Each member generates a **sender key** (a symmetric hash ratchet) and
distributes it once to every other member over the pairwise channels. Group
messages are then encrypted once with the sender key.

- **Pros:** O(1) encryption per message, O(n) only on key rotation; well-trodden
  design.
- **Cons:** rekey on every membership change for full PCS; sender keys must be
  re-sent to new members; weaker PCS than per-message DH.
- **Recommended as the practical mid-term target.**

### A3. MLS — Messaging Layer Security (RFC 9420)
TreeKEM-based group key agreement: efficient (log n) membership changes,
group-wide forward secrecy and post-compromise security.

- **Pros:** the modern standard; scales; strong security properties; designed
  exactly for this problem.
- **Cons:** substantial implementation and **must not be rolled clean-room
  lightly** — far larger surface than Double Ratchet. Would likely need a vetted
  MLS library, which reopens the dependency/license analysis (see
  SECURITY_MODEL §5.5). Also assumes a "Delivery Service" for ordering that we'd
  have to approximate serverlessly.
- **Long-term aspiration**, contingent on an auditable MLS implementation.

### Cross-cutting group problems (apply to all of the above)
- **Membership & admin:** who can add/remove; changes signed by an admin key or
  carried as authenticated group-state operations; propagated over the mesh.
- **State convergence without a server:** no global order. Use causal metadata
  (Lamport timestamps / vector clocks) for "happened-before"; accept eventual
  consistency; surface conflicts in UI rather than hiding them.
- **Group identity:** a `groupID` (random) plus a signed, replicated roster.
- **Delivery:** groups ride the existing flood mesh; dedup already handles the
  multi-path fan-out. Add per-group seen-tracking.

**Recommended path:** A1 → A2, defer A3 until there's an auditable MLS option.

---

## B. Long-Distance / Non-Bluetooth Transport

Bluetooth covers "in the same room/building, or a chain of people between."
Reaching someone in another city or country needs a wider transport — without
betraying the privacy model. **The encrypted payload stays identical; we add
transports beneath it.**

### B0. Foundation: a `Transport` abstraction (do this early)
Refactor so BLE is just one implementation of a `Transport` protocol
(send/receive opaque frames; report reachability). `MeshService` then runs over
any mix of transports. This is cheap to do now and unlocks everything below.
**This is the single most important enabler and should land before Phase 7.**

### B1. Extend local reach (still fully offline)
Higher-bandwidth / longer-range local transports to grow the mesh:
- **Multipeer Connectivity / Wi-Fi Aware:** Apple frameworks; tens of meters,
  much higher throughput than BLE; still infrastructure-free.
- **LoRa** (via an external module): kilometer-range, tiny bandwidth — excellent
  for off-grid/rural; great fit for short text. Needs hardware.

### B2. Delay-tolerant store-and-forward ("data mules")
Generalize the mesh's store-and-forward: a device holds **ciphertext addressed
to a recipient identity** and delivers it when it later encounters that
recipient (or a relay closer to them). Physical movement carries messages
between disconnected clusters. Pure extension of what we have; no internet.
- Requires **async first contact (X3DH-style prekeys)** — already a tracked
  item — since the recipient is usually offline.

### B3. Internet transport (opt-in, privacy-preserving)
When the internet is available and the user opts in, carry the same E2E
ciphertext over IP. Options, roughly in order of fit with our values:

1. **Federated zero-knowledge relays (recommended).** Dumb, replaceable,
   community-/self-hostable mailbox relays that store **ciphertext only** for
   offline recipients (conceptually Nostr-relay-like). No relay can read content;
   users choose/run their own; no single point of trust. Pairs naturally with B2
   (a relay is just an always-on "data mule").
2. **Onion routing (Tor).** Route between users via Tor hidden services (the
   Briar approach) for strong **metadata** protection — hides who talks to whom,
   not just content. No central server; requires Tor and online presence.
3. **Direct P2P over internet.** NAT traversal (ICE/STUN) for direct links;
   honest caveat: reliable traversal usually needs a TURN relay, which is
   infrastructure — so this is partial at best.

### Security considerations specific to non-BLE (see SECURITY_MODEL)
- **Metadata is the main new risk.** BLE leaks local presence; the internet
  leaks IP, timing, and relay-visible routing. Mitigate with onion routing,
  **sealed-sender** (hide sender from relays), message padding, and cover
  traffic.
- **Relays must be zero-knowledge and federated** — never able to read content,
  never a mandatory single party.
- **Replay/ordering across heterogeneous transports** must be consistent
  (the mesh packet id + ratchet already guard content; extend dedup horizon for
  long-lived relayed packets).
- **Async first contact (X3DH)** becomes essential, with its prekey
  exhaustion/replay tradeoffs.

**Recommended path:** B0 (Transport abstraction) → B2 (delay-tolerant relaying)
→ B3.1 (federated zero-knowledge relays) → B3.2 (Tor for metadata), with B1 as
opportunistic local-reach wins.

---

## Sequencing summary

1. **`Transport` abstraction (B0)** — enabler, do before Phase 7.
2. **Async first contact (X3DH)** — already tracked; unblocks B2/B3 and offline groups.
3. **Group chats A1 → A2.**
4. **Delay-tolerant store-and-forward (B2).**
5. **Federated zero-knowledge relays (B3.1), then Tor (B3.2).**
6. **MLS (A3) and LoRa/Wi-Fi-Aware (B1)** as longer-term / opportunistic.

Each of these is a phase in its own right and will get its own design doc and —
for anything touching cryptography — its own test vectors and a note in the
audit-readiness list before it can be called secure.
