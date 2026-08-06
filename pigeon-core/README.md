# pigeon-core

Pigeon's **pairwise end-to-end-encrypted messaging core**, built on **Olm** via
the audited [`vodozemac`](https://crates.io/crates/vodozemac) crate. It provides
async-first session establishment plus the Double Ratchet — forward secrecy,
post-compromise security, and tolerance of out-of-order and skipped messages.

The ratchet math is vodozemac's. This crate deliberately hand-rolls no
cryptographic protocol; it replaced the earlier clean-room Swift `PigeonCrypto`
package (Noise XX + X3DH + Double Ratchet) for exactly that reason.

## What Pigeon keeps on top of Olm

Olm authenticates sessions with Curve25519 keys, but does not by itself tie a
peer's Curve25519 identity key to a stable, human-verifiable identity. Pigeon's
trust model rests on a long-term **Ed25519 identity key** — the safety-number
root, verified out of band (in person, via QR).

So pigeon-core keeps exactly one piece of protocol trust: the Ed25519 identity
key **signs** Olm's Curve25519 identity key (the *identity binding*,
`IdentityBundle`) and every published prekey (`PrekeyBundle`). Verifying a peer's
safety number therefore authenticates the whole channel. The Ed25519 identity is
independent of the Olm account, so re-pickling or rotating Olm keys never churns
safety numbers.

## Lifecycle

1. Each device owns one `Account` (Ed25519 identity + Olm account + prekeys).
2. A recipient publishes a `PrekeyBundle` ahead of time — via QR, mesh gossip,
   or a relay.
3. An initiator calls `Session::establish_outbound` against a *verified* bundle,
   producing the session and an `Initiation` (identity bundle + first Olm
   pre-key message) to send.
4. The recipient calls `Session::establish_inbound` when it next comes online,
   recovering the session and the first plaintext.
5. Both ends exchange traffic with `Session::encrypt` / `Session::decrypt`.

Async-first is the point: Pigeon peers are frequently offline, so establishment
must complete from a stored bundle with no interactive round trip.

## Layout

| File          | Contents                                                        |
| ------------- | --------------------------------------------------------------- |
| `identity.rs` | `IdentityKeypair`, `IdentityBundle` — the Ed25519 → Curve25519 binding. |
| `account.rs`  | `Account`: identity + Olm account + prekeys + persistence.      |
| `prekey.rs`   | `PrekeyBundle` (signed prekey / one-time prekeys).              |
| `session.rs`  | `Session`, `Initiation` — establishment and traffic.            |
| `wire.rs`     | protobuf encode/decode for the `pigeon.wire.v1` schema.         |
| `error.rs`    | `Error`.                                                        |

Wire types use the shared Protocol Buffer schema at
`proto/pigeon/wire/v1/pigeon_wire.proto`, so every client speaks one format.
The crate is `#![forbid(unsafe_code)]` and links no bindings — Swift reaches it
through [`pigeon-ffi`](../pigeon-ffi).

## Checks

```sh
cargo fmt --check --manifest-path pigeon-core/Cargo.toml
cargo clippy --manifest-path pigeon-core/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path pigeon-core/Cargo.toml
```

Behavioral tests (full pairwise conversations, out-of-order delivery, tampering,
persistence round-trips) live in `tests/pairwise.rs`.

## Status

Pre-release and **not independently audited**. See
[`SECURITY_MODEL.md`](../docs/SECURITY_MODEL.md) for the threat model and the
audit blockers.

## License

**GNU Affero General Public License v3.0 only** (`AGPL-3.0-only`) — see
[LICENSE](LICENSE). The protocol and cryptography stay copyleft so modified
versions offered to users cannot be taken closed.
