# Architecture review for 1.4.0

This is a code and design review, not an independent security audit. The basic split between the Swift app, transactional Rust cryptographic core, opaque transports, and federated relay is sound. A broad rewrite would increase risk. The changes below target boundaries where an apparently successful operation can lack durable delivery, or where metadata leaves the device unexpectedly.

Review status on 2026-10-04: items 1–5 have code fixes in this branch. Item 6
has a global socket cap, per-IP cap based on the TCP peer address, and unauthenticated
deadline; deployments behind a reverse proxy must set compatible upstream limits.
Item 7 now has a 4 MiB aggregate fragment budget across BLE sources, but checkpoint
size and latency still need stress measurements. Item 8
remains open. The invite flow is still awaiting live multi-device validation.

## Release correctness and privacy

1. **Preserve retry disposition through mesh deduplication.** `MeshRouter::ingest` records a packet ID before `MeshService` asks the session layer to consume it (`pigeon-mesh/src/packet.rs`, `Pigeon/Pigeon/Core/Mesh/MeshService.swift`). If consumption returns `retryAfterRestart`, a second relay delivery of the same packet in the same process is classified as a duplicate and returned as `consumed`; `RelayTransport` then acknowledges it. Keep retrying that packet until the core has durably classified it. Test repeat delivery while the vault is locked and after a save failure.
2. **Confirm pairwise relay deposits.** `RelayTransport.attemptDeposit` treats a WebSocket send as success without awaiting a relay `published` reply (`Pigeon/Pigeon/Core/Transport/RelayTransport.swift`). The relay can reject a new mailbox at capacity or evict queued ciphertext to meet its byte ceiling (`pigeon-relay/src/mailbox/store.rs`). Give deposits IDs, retain them through a positive relay receipt, and surface a bounded retry state. An accepted relay receipt cannot promise delivery to the recipient because pairwise mailboxes are ephemeral; the sender must retain end-to-end retry until recipient acknowledgement.
3. **Limit relay probes to enabled endpoints.** `RelaySettingsView` probes disabled relays every 20 seconds when settings are open, exposing IP address and timing after a user has disabled one. The product decision for 1.4.0 keeps the recommended relay and push active on a fresh install. Probe enabled relays only, and make the default network connection clear in the first-run UI and privacy text.
4. **Show a persistent storage-failure state.** `SessionManager.persist()` marks persistence unhealthy after a failed save, but only records a diagnostic event. A visible non-dismissable error should explain that sending and receiving are paused and offer the supported recovery action. Never resume a live ratchet from a stale sealed checkpoint.
5. **Do not share an invalid contact card.** `SessionManager+UI.swift` substitutes an empty relay signature if signing fails. Fail card creation and show a recoverable error instead of silently removing advertised reachability for contacts.

## Capacity and scale

6. **Bound unauthenticated relay sockets.** Both WebSocket services allocate a writer task and channel before authentication, without an application connection cap or handshake timeout. Add per-IP and global limits plus a deadline; document proxy limits. This is a proven unbounded path, while its practical exhaustion threshold needs load testing.
7. **Measure checkpoint and BLE memory costs before raising group limits.** Each core command clones and serializes the whole checkpoint, currently bounded at 64 MiB; BLE reassembly limits permit roughly 256 MiB of fragment payloads across 16 peers. Add stress benchmarks and a global reassembly byte budget. These are scaling estimates, not measured latency or memory leaks.
8. **Bound historical relay metadata.** Inactive authorization and coordinator receipt heads must survive for anti-rollback, but unrestricted durable tombstones grow over time. Enforce a database budget, monitor capacity, and specify an archival or maintenance procedure that never resets a group's sequence.

## Architecture decision

Keep OpenMLS and Olm inside `pigeon-core`, keep Swift as the platform and UI boundary, and keep relays blind to content. Add a dedicated invite ingress flow for shareable links rather than exposing plaintext join material or an admin's long-term identity in a public URL. Admission and invite joining have separate design documents in this directory. The invite flow stays at the existing 128-member limit for 1.4.0; larger communities require performance evidence and likely a different topology.

## Follow-up verification

An installation sentinel now prevents a missing vault key or encrypted store from silently creating empty history while the old identity remains. Physical multi-device and locked-delivery testing remains mandatory. The public universal-link association file also needs verification on the deployed website; in-app QR and paste paths are covered by simulator tests.
