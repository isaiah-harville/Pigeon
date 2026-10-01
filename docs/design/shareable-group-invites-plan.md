# Shareable Group Invites Implementation Plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` task by task. Steps use checkboxes for review.

**Goal:** Let up to 128 people request membership from a revocable link or QR; public invitations are processed automatically by an online admin, and private invitations wait for approval.

**Architecture:** A link carries a group locator, expiry, random bearer, and a short-lived pseudonymous Olm inbox prekey. The requester uses a separate ephemeral Olm account so the relay sees neither party's root identity. The first encrypted message contains a root-signed intent and ephemeral reply address. The admin returns the existing owner-bound join request over the encrypted session, then the requester returns root-bound MLS join material; an authorized admin stages the existing coordinator-serialized MLS Add and Welcome. Each transition and ratchet state commits before outbound delivery or relay acknowledgement.

**Tech Stack:** Rust 2024, prost, vodozemac 0.10, OpenMLS 0.9, UniFFI, Swift 6, existing blind relay.

**Spec:** `docs/design/shareable-group-invites.md`

## Global constraints

- No Pigeon accounts, phone numbers, payment identifiers, plaintext relay requests, or long-term admin root identity in a public link.
- No new cryptographic primitives or services. Use existing `vodozemac`, Ed25519 identity boundary, and relay.
- Current group size limit is 128; current policy and coordinator receipt decide membership.
- Pending is never presented as membership. Offline admins can delay joining.
- A relay item is acknowledged only after decrypting, deduplicating, and committing the next state.

---

### Task 1: Versioned invite and request formats

**Files:** `proto/pigeon/wire/v1/identity.proto`, `pigeon-core/src/identity/group/invite.rs`, `pigeon-core/src/identity/group/mod.rs`, `pigeon-core/src/identity/mod.rs`, `pigeon-core/src/lib.rs`, `pigeon-core/tests/group_shareable_invites.rs`.

**Interfaces:** `GroupInviteTicket::decode/encode`, `GroupInviteTicket::validate(now_ms)`, `GroupInviteMode::{Public,Private}`, `GroupInviteIntent::create(identity,ticket,request_id,reply_prekey)` and `verify(ticket)`. A ticket has version 1, 32-byte group and coordinator IDs, 32-byte coordinator public key, canonical WSS relay URL, 32-byte inbox address, 32-byte Olm Curve25519 identity and fallback prekey, 32-byte bearer, expiry, and mode. The intent signs a domain-separated transcript binding ticket digest, requester root, request ID, and reply prekey. Bounds apply before decoding large fields.

- [ ] Write tests for ticket round trip, malformed/expired ticket rejection, and a valid root-signed intent that fails if the ticket, group, coordinator, reply key, or request ID changes.
- [ ] Run `cargo test --manifest-path pigeon-core/Cargo.toml --test group_shareable_invites` and observe failure caused by missing feature.
- [ ] Add bounded protobuf formats and validation. Do not put the admin's root key in the ticket.
- [ ] Run the same test and require a pass.
- [ ] Commit the wire foundation.

### Task 2: Confidential anonymous request envelope

**Files:** `pigeon-core/src/identity/group/invite_session.rs`, `pigeon-core/tests/group_shareable_invites.rs`, `proto/pigeon/wire/v1/identity.proto`.

**Interfaces:** `InviteInbox::new/export/import`, `InviteRequester::new/export/import`, `InviteRequester::start(ticket,intent) -> envelope`, `InviteInbox::receive(envelope) -> (intent,reply_session)`, `InviteReplySession::encrypt/decrypt`. Account state is opaque secret and must be sealed by the core checkpoint before outbound delivery. The first Olm initiation uses a fresh ephemeral identity, while the root-signed intent stays inside ciphertext. Each envelope binds the group/inbox/request ID in authenticated plaintext.

- [ ] Add a test that an observing relay can decode only ephemeral routing keys, while the inbox recovers and verifies the requester root inside ciphertext.
- [ ] Run the focused test and observe failure.
- [ ] Implement the envelope using `vodozemac`; reject modified routing fields, tampered ciphertext, replayed request IDs, and wrong inbox.
- [ ] Test account/session pickle restart before and after the first reply; require no ratchet rollback.
- [ ] Commit the cryptographic envelope.

### Task 3: Durable request state and admin policy

**Files:** `proto/pigeon/wire/v1/client.proto`, `pigeon-core/src/client/command.rs`, `pigeon-core/src/client/event.rs`, `pigeon-core/src/client/transaction/invite.rs`, `pigeon-core/src/client/transaction/checkpoint.rs`, `pigeon-core/tests/group_shareable_invites.rs`.

**Interfaces:** commands for creating/revoking an invite, starting a join, receiving an invite request/reply, approving or declining a private request, and applying coordinator receipts. Snapshot includes outstanding invites and requests. Outbound effects address the invite inbox and requester's ephemeral reply inbox.

- [ ] Test crash after staging each outbound effect, replay of each inbound item, stale/revoked invite, removed admin, public automatic processing, private pending approval, and full 128-member group.
- [ ] Run focused tests and observe expected failures.
- [ ] Implement checkpoint-backed invite accounts, sessions, pending requests, and tombstones with explicit bounds and expiry. Stage existing owner-bound `GroupJoinRequest`, `GroupJoinMaterial`, MLS Add, and Welcome only through committed commands.
- [ ] Run focused and full core tests; commit the transactional flow.

### Task 4: FFI and app-facing contract

**Files:** `pigeon-ffi/src/client.rs`, `Pigeon/PigeonFFI/Sources/PigeonFFI/PigeonCore.swift`, `Pigeon/PigeonFFI/Tests/`, `proto/pigeon/wire/v1/client.proto`.

**Interfaces:** Swift facade encodes invite commands and parses invite snapshot/events; it never handles a private Olm pickle or owner root key outside the encrypted core checkpoint. Link encoding uses a fragment and rejects oversized or unsupported payloads.

- [ ] Write Swift round-trip tests for public/private ticket modes, malformed links, and request state transitions.
- [ ] Run `swift test --package-path Pigeon/PigeonFFI` and observe failure.
- [ ] Expose only byte-oriented transaction commands and safe ticket metadata through UniFFI facade; regenerate bindings.
- [ ] Run `cargo test --manifest-path pigeon-ffi/Cargo.toml`, XCFramework build, Swift tests, and iOS build; commit.

### Task 5: Relay and app integration gate

**Files:** owned by the relay and app workstreams.

- [ ] Add a bounded durable opaque invite mailbox with write-before-ack, TTL, quota, rate limits, and replay-safe delivery.
- [ ] Build create/share/scan/approve/decline/pending UI, display public-link disclosure, and rotate/revoke controls.
- [ ] Verify relay restart and app restart at each transition, then physical multi-device and locked-delivery behavior before calling 1.4.0 releasable.
