# pigeon-relay

`pigeon-relay` is the Rust zero-knowledge relay server. It is a blind,
federated ciphertext mailbox for peers who are out of local range.

The relay stores and forwards opaque ciphertext addressed by recipient public
key. It cannot read messages, authenticate content, or forge trusted sessions;
those properties live end-to-end in Pigeon clients.

## Durable state and restarts

Pairwise mailboxes are intentionally memory-only. A restart discards any
unacknowledged pairwise envelopes, and senders retransmit them from their durable
client queues.

Group mailboxes and the MLS coordinator are different: group registrations,
opaque group entries, capability state, cursors, dissolution tombstones,
coordinator candidates, and signed receipt chains are committed to SQLite before
the relay acknowledges a mutation. Their storage directory is configured with
`PIGEON_RELAY_STATE_DIR` and defaults to `/var/lib/pigeon-relay` in the container.
Mount that directory on persistent storage:

```sh
docker run -p 8080:8080 \
  -v pigeon-relay-state:/var/lib/pigeon-relay \
  -e PIGEON_COORDINATOR_SIGNING_SEED_HEX="<64-hex-character-secret>" \
  ghcr.io/isaiah-harville/pigeon/relay:latest
```

The coordinator signing seed is required in release builds. Generate it from a
cryptographically secure source, keep it in a secret manager, and preserve it
across restarts. Startup fails closed when the configured seed does not match the
coordinator identity bound into the stored receipt logs. Do not rotate it for an
existing deployment without explicit client-side coordinator recovery.

## Data retained at rest

The durable database contains opaque MLS ciphertext and coordinator candidates,
plus group-level metadata needed for authorization, ordering, replay prevention,
retention, and recovery. This includes group and capability identifiers,
sequence/cursor state, timestamps, sizes, revocations, dissolution tombstones,
and signed coordinator receipts. It contains no message plaintext or private
client keys, but a relay operator can observe and retain this metadata until TTL
or cursor reclamation removes it.

Pairwise ciphertext and APNs device tokens remain memory-only and are not part of
the durable database.

## Backups

Back up `PIGEON_RELAY_STATE_DIR` and the coordinator signing seed as one recovery
set. Stop the relay before a filesystem copy, or use a SQLite-aware snapshot.
Copying only the main database files while WAL files are active can omit committed
state. Restrict both the backup and live volume to the relay operator; the data is
opaque to the relay but still contains sensitive traffic metadata and ciphertext.

For deployment examples and the complete configuration table, see
[Host a Relay](https://docs.pigeonwire.app/host-a-relay/). For the trust and
metadata analysis, see
[Security Model §6.1](https://docs.pigeonwire.app/SECURITY_MODEL/#61-relay-transport-remote-delivery-opt-in).

## Checks

```sh
cargo fmt --check --manifest-path pigeon-relay/Cargo.toml
cargo clippy --manifest-path pigeon-relay/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path pigeon-relay/Cargo.toml
```
