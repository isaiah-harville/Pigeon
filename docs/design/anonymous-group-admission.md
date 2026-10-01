# Anonymous group registration admission

## Goal

An anonymous client can create a group on a federated relay without an account. One cheap self-signed registration must not reserve a live group slot forever. Existing members must be able to resume an inactive group without resetting its authorization or sequence.

## Admission

The relay's group WebSocket issues a short-lived random challenge only after it validates the signed registration and confirms that the coordination ID is new. The challenge is bound to that registration's canonical transcript. The client searches for an eight-byte nonce such that SHA-256 of `pigeon.relay.group.admission.v1`, the challenge, the registration transcript, and the nonce has the configured number of leading zero bits. The app solves this off the main actor, then resends the registration with the nonce. A challenge is valid for one registration on one connection for 60 seconds. The relay retains the per-connection and global registration rate limits. Existing identical registrations and authenticated operations do not pay this cost.

The relay can vary work difficulty by deployment. The default must be benchmarked on supported phones before release. Proof of work raises the cost of Sybil registration but does not prevent a well-funded attacker; a hard group limit and operator monitoring remain necessary. No phone number, account, persistent client identifier, or payment credential is introduced.

## Inactive group leases

Successful authenticated activity extends a configurable group lease. After the lease ends, the relay removes the group from the active in-memory capacity count, but retains its exact capability set, authorization generation, cursors, next message sequence, controller binding, and coordinator receipt head on disk. It does not accept a fresh registration that could overwrite this state. A current capability holder may authenticate and reactivate the group if capacity is available. The relay confirms reactivation only after the durable state is loaded. If capacity is full, the client retries without discarding local MLS state.

Expired ciphertext follows the existing message TTL. Dissolution remains terminal after its read grace period. A database migration preserves all existing groups and gives them a full initial lease. Historical authorization remains durable, so operators need a separate disk budget and maintenance policy; an active-group limit alone is not a disk limit.

## Invariants and tests

- A stale admin cannot replace a dormant group's capabilities or reset its generation or sequence.
- A removed capability cannot reactivate, read, or append.
- A current member can reactivate across a relay restart without an owner online.
- A one-byte append followed by lease expiry frees an active slot while preserving message numbering.
- Malformed, expired, reused, or wrong-registration admission solutions fail without allocating capacity.
- The app keeps the registration effect pending until the relay acknowledges it and shows a recoverable capacity error.

The release needs protocol-version negotiation, Rust unit and live socket tests, Swift protocol tests, an iOS build, Docker smoke tests, and physical-device timing and locked-delivery tests.
