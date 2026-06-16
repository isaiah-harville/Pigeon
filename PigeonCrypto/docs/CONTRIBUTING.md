# Contributing to PigeonCrypto

Read the root contributor guide first, then use `PigeonCrypto/CONTRIBUTING.md`
for package-specific expectations.

## Checks

```sh
swift test --package-path PigeonCrypto
swift-format lint --recursive --parallel PigeonCrypto
```

Do not implement primitive cryptographic algorithms or add dependencies without
a documented security reason.
