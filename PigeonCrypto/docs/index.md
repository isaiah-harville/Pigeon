# PigeonCrypto

`PigeonCrypto` is the standalone Swift package for Pigeon's cryptographic
protocol code. It composes Apple CryptoKit primitives into Noise XX, Double
Ratchet, identity bundles, local secret boxes, and secure session state.

The package is intentionally dependency-free outside CryptoKit and has not been
independently audited.

## Test

```sh
swift test --package-path PigeonCrypto
```
