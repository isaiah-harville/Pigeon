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

## License

Licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`) — see [LICENSE](LICENSE). This package is reusable messaging
core code: people can use it to build new apps, but modified versions offered to
users must keep their source available under the AGPL.
