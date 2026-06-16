# Contributing to PigeonMesh

Read the root contributor guide first, then use `PigeonMesh/CONTRIBUTING.md` for
package-specific expectations.

## Checks

```sh
swift test --package-path PigeonMesh
swift-format lint --recursive --parallel PigeonMesh
```

Keep this package platform-agnostic, dependency-free, and easy to test without
radios, sockets, or app state.
