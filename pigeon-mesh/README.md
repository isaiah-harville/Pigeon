# pigeon-mesh

Pigeon's **transport-agnostic mesh layer**: packet framing, dedup/TTL flood
routing, BLE-sized fragmentation and reassembly, and the identity-addressed
session envelope.

It carries **opaque bytes** and performs **no cryptography**. Payloads are
already ciphertext by the time they reach here (see
[`pigeon-core`](../pigeon-core)); the mesh only reads routing headers so it can
deduplicate, relay, fragment, and address. That separation is deliberate: the
layer that decides where a packet goes never needs to be trusted with what's
inside it.

It is also the shared, platform-independent definition of the wire format —
every client speaks the same bytes by linking this crate rather than
re-implementing framing per platform. Its only dependency is `getrandom`, for
packet ids.

## The three layers

Each is a deterministic, fixed-width wire format.

- **`packet`** — the `MeshPacket` envelope (`version ‖ ttl ‖ packetID ‖
  payload`), a `SeenCache` for duplicate suppression, and `MeshRouter`, which
  makes the flood-routing decision: deliver locally, relay onward, or both.
  TTL bounds how far a packet travels; the seen-cache stops it circling.
- **`fragment`** — `Fragmenter` splits a logical message into pieces that fit a
  small BLE MTU; `Reassembler` puts them back together, tolerating reordering
  and duplication and bounded against memory exhaustion (caps on message size
  and concurrent in-flight messages).
- **`envelope`** — the identity-addressed `SessionEnvelope`
  (`sender ‖ recipient ‖ type ‖ payload`), routed *inside* a packet's payload,
  so a relaying device can forward for a pair it has no session with.

## Usage

```rust
use pigeon_mesh::{MeshRouter, MeshPacket};

let mut router = MeshRouter::new(/* default_ttl */ 5, /* seen_capacity */ 512);

// Originate: wrap a ciphertext payload in a fresh packet to broadcast.
let packet = router.originate(ciphertext);
let bytes = packet.encode();

// Receive: decode, then let the router decide what to do with it.
let reception = router.ingest(MeshPacket::decode(&bytes)?);
if let Some(payload) = reception.deliver { /* hand up to the session layer */ }
if let Some(relay) = reception.relay { /* rebroadcast on every link */ }
```

The transport driver (CoreBluetooth on iOS) lives in the app and feeds bytes
through this crate; Swift reaches it via [`pigeon-ffi`](../pigeon-ffi).

## Checks

```sh
cargo fmt --check --manifest-path pigeon-mesh/Cargo.toml
cargo clippy --manifest-path pigeon-mesh/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path pigeon-mesh/Cargo.toml
```

Behavioral tests live in each module — framing round-trips, TTL expiry, dedup,
fragmentation under reorder/duplication, and reassembly bounds.

## Status

Pre-release and **not independently audited**. A mesh relay sees traffic
patterns (who broadcasts, when, how much) even though it cannot read content;
metadata minimization is tracked in
[`SECURITY_MODEL.md`](../docs/SECURITY_MODEL.md).

## License

**GNU Affero General Public License v3.0 only** (`AGPL-3.0-only`) — see
[LICENSE](LICENSE). The wire format and network code stay copyleft so modified
versions offered to users cannot be taken closed.
