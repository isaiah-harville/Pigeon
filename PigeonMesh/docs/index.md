# PigeonMesh

`PigeonMesh` is the dependency-free Swift package for transport-agnostic mesh
logic: fragmentation, reassembly, packet IDs, TTL, duplicate suppression, relay
decisions, and session envelopes.

It handles opaque bytes only. End-to-end encryption and identity live above it;
BLE, relay, and future transports live below it.

## Test

```sh
swift test --package-path PigeonMesh
```
