# Pigeon

Pigeon is an end-to-end encrypted mesh messenger for iOS. Devices can exchange
the same ciphertext over local Bluetooth mesh links or, when enabled, over
federated zero-knowledge relays for peers outside local range.

The project is pre-release and not independently audited. Treat the
documentation as the current design and implementation map, not as a security
certification.

## What exists now

- On-device Ed25519 identity with Keychain storage.
- QR-based contact exchange with display name, signed identity bundle, and
  signed relay endpoints.
- Olm session establishment and the Double Ratchet (async-first, via the audited
  `vodozemac` crate) in the Rust `pigeon-core` package, bridged to the app
  through the `PigeonCore` XCFramework.
- BLE mesh transport, fragmentation, duplicate suppression, TTL, and local
  store-and-forward behavior.
- Encrypted local storage and per-chat ephemeral mode.
- Optional zero-knowledge relay transport and Rust relay server.

## Where to start

- [Security Model](SECURITY_MODEL.md) for the threat model and audit blockers.
- [Roadmap](ROADMAP.md) for shipped, active, planned, and horizon work.
- [API Reference](API.md) for generated pigeon-core, PigeonMesh, and PigeonRelay
  API docs.
- [Contributing](CONTRIBUTING.md) for local checks and review expectations.
