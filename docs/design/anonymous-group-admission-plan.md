# Anonymous Group Admission Implementation Plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` task by task. Steps use checkboxes for review.

**Goal:** Anonymous registration work and inactive leases prevent a cheap, permanent active-group slot claim without resetting group authorization.

**Architecture:** A signed new-group registration receives a one-connection proof-of-work challenge; the app solves it off the main actor and retries the same durable registration effect. Inactive groups leave the active capacity count but keep exact authorization and sequence on disk, then reactivate after a current capability proves possession.

**Tech Stack:** Rust 2021, axum WebSocket, rusqlite, SHA-256, Swift 6/CryptoKit, URLSessionWebSocketTask.

**Spec:** `docs/design/anonymous-group-admission.md`

## Global constraints

- No accounts, phone numbers, payment identifiers, or plaintext group content on the relay.
- Preserve authorization generation, capabilities, cursors, and next sequence across expiry and restart.
- Do not acknowledge a registration or reactivation before durable state commits.
- Physical-device proof-of-work timing and locked delivery remain release gates.

---

### Task 1: Wire challenge and proof

**Files:** `pigeon-relay/src/group/protocol.rs`, `pigeon-relay/src/group/connection.rs`, `pigeon-relay/src/group/tests.rs`, `Pigeon/Pigeon/Core/Transport/GroupRelayProtocol.swift`, `Pigeon/Pigeon/Core/Transport/GroupRelayTransport.swift`, `Pigeon/PigeonTests/GroupRelayConnectionTests.swift`.

**Interfaces:** Add `registration_challenge { nonce, difficulty }` server frame and optional `admission_solution` on `register`. Define `SHA256("pigeon.relay.group.admission.v1" || challenge_nonce[32] || SHA256(registration_transcript) || solution[8])` with leading-zero difficulty bits. Challenge expires after 60 seconds and is bound to one registration digest on one socket. Bump group protocol version in Rust and Swift together.

- [ ] Write a Rust test where a new valid signed registration receives a challenge and cannot register with a wrong digest, expired challenge, or insufficient work. Assert a valid solution registers once.
- [ ] Run `cargo test --manifest-path pigeon-relay/Cargo.toml group::` and observe the expected failure.
- [ ] Implement bounded challenge state and hash verification. Keep the existing per-connection and global rate limits.
- [ ] Run the same Rust test and require a pass.
- [ ] Write a Swift test that feeds a challenge to a pending registration, verifies the computed solution against a test vector, and proves a repeated registration effect is sent after the challenge.
- [ ] Run the focused Xcode test and observe the expected failure.
- [ ] Implement a cancelable background solver in the transport. Keep the core registration effect pending until `registered` arrives.
- [ ] Run Swift tests and the iOS build; commit the protocol slice.

### Task 2: Durable inactive leases

**Files:** `pigeon-relay/src/durable.rs`, `pigeon-relay/src/group/store.rs`, `pigeon-relay/src/group/connection.rs`, `pigeon-relay/src/group/tests.rs`.

**Interfaces:** Schema v5 adds `last_activity_at INTEGER NOT NULL` and `inactive INTEGER NOT NULL` to `groups`. Migration gives existing groups `last_activity_at = unixepoch()` and `inactive = 0`. `Store::expire_at` archives an unrevoked group after its configured lease, preserving any unexpired ciphertext and all authorization state. `GroupJournal::load` loads active groups only; `load_inactive_capability` supplies a public key for a challenge, and `activate_after_auth` loads the full unchanged group after signature verification and capacity check.

- [ ] Add a store test: register, append one byte, expire past the lease, register another group at the one-group active cap, then reactivate the first after the second expires. Assert sequence continues at 2 and old authorization persists.
- [ ] Add durable restart tests for revoked capability, stale re-registration, changed generation, cursor preservation, and coordinator receipt head preservation.
- [ ] Run `cargo test --manifest-path pigeon-relay/Cargo.toml group::` and observe failures.
- [ ] Implement the schema migration and inactive load/activation transaction. Make durable writes fail-stop before any success reply.
- [ ] Run group, coordinator, and live socket tests; commit the lease slice.

### Task 3: Capacity behavior and release documentation

**Files:** `pigeon-relay/src/config.rs`, `pigeon-relay/README.md`, `docs/host-a-relay.md`, `docs/SECURITY_MODEL.md`, `Pigeon/Pigeon/Features/Groups/CreateGroupView.swift`.

- [ ] Add config tests for admission difficulty and lease duration, including invalid values and migration defaults.
- [ ] Run the focused config tests and observe failures.
- [ ] Add documented configuration. Show a recoverable pending/capacity state in group creation rather than implying relay registration completed at local group creation.
- [ ] Run `cargo test --workspace`, `swift test --package-path Pigeon/PigeonFFI`, `xcodebuild build`, `cargo fmt --check`, and a Docker build and health smoke test.
- [ ] Record the physical-device timing and locked-delivery checks as unmet release gates; commit the documentation and UI slice.
