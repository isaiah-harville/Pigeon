# PigeonMesh

`PigeonMesh` is a dependency-free Swift package for transport-agnostic mesh
logic. It has no CoreBluetooth dependency; app transports feed bytes into it.

## Contains

- `Fragmentation.swift` — fragmentation and reassembly for small transport MTUs.
- `MeshPacket.swift` — packet IDs, TTL, duplicate suppression, and relay
  decisions.
- `SessionEnvelope.swift` — dependency-free envelope for session messages.

## Test

```sh
swift test --package-path PigeonMesh
```

## Design notes

The package handles opaque bytes only. End-to-end encryption and identity live
above it in the app and `PigeonCrypto`; radios, relays, and future transports
live below it behind the app's `Transport` protocol.
