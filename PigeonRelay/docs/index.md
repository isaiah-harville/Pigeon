# PigeonRelay

`PigeonRelay` is the Rust zero-knowledge relay server. It is a blind,
federated ciphertext mailbox for peers who are out of local range.

The relay stores and forwards opaque ciphertext addressed by recipient public
key. It cannot read messages, authenticate content, or forge trusted sessions;
those properties live end-to-end in Pigeon clients.

## Checks

```sh
cargo fmt --check --manifest-path PigeonRelay/Cargo.toml
cargo clippy --manifest-path PigeonRelay/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path PigeonRelay/Cargo.toml
```
