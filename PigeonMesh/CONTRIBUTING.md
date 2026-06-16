# Contributing to PigeonMesh

Read the root [CONTRIBUTING.md](../CONTRIBUTING.md) first.

Keep this package platform-agnostic and dependency-free. It should remain easy
to test without radios, sockets, or app state.

## Checks

```sh
swift test --package-path PigeonMesh
swift-format lint --recursive --parallel PigeonMesh
```

## Mesh expectations

- Treat payloads as opaque ciphertext.
- Keep packet encoding deterministic.
- Preserve duplicate suppression and TTL semantics when changing routing logic.
- Add tests for replay, duplicate, expiry, and malformed-frame behavior.
