# PigeonCrypto

`PigeonCrypto` is a standalone Swift package for Pigeon's identity-agnostic
cryptographic protocol code.

It is intentionally dependency-free outside Apple CryptoKit so the code remains
small enough to audit.

## Contains

- `Primitives.swift` — CryptoKit wrappers and domain-separated KDF helpers.
- `NoiseHandshake.swift` — clean-room Noise XX handshake state machine.
- `DoubleRatchet.swift` — Signal-style Double Ratchet state and message
  encrypt/decrypt.
- `IdentityBundle.swift` — Ed25519 identity binding for the X25519 Noise static
  key.
- `SecretBox.swift` — local authenticated encryption helper.
- `SecureSession.swift` — handshake-to-ratchet composition used by the app.

## Test

```sh
swift test --package-path PigeonCrypto
```

## Security status

This package has not been independently audited. It composes CryptoKit
primitives but still needs byte-level Noise test-vector validation and external
review before production security claims.

## License

Licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`) — see [LICENSE](LICENSE). This package is reusable messaging
core code: people can use it to build new apps, but modified versions offered to
users must keep their source available under the AGPL.
