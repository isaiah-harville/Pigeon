# Contributing to PigeonCrypto

Read the root [CONTRIBUTING.md](../CONTRIBUTING.md) first.

This package is the highest-review surface in the repo. Keep it dependency-free
unless there is a strong, documented security reason.

## Checks

```sh
swift test --package-path PigeonCrypto
swift-format lint --recursive --parallel PigeonCrypto
```

## Crypto expectations

- Do not implement primitive cryptographic algorithms.
- Domain-separate every derived key.
- Keep wire formats deterministic and covered by tests.
- Prefer small, direct code over abstraction that makes review harder.
- Update the security model when protocol composition changes.
