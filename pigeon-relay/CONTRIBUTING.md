# Contributing to pigeon-relay

Read the root [CONTRIBUTING.md](../CONTRIBUTING.md) first.

The relay is untrusted infrastructure by design. It must remain a blind mailbox:
no plaintext, no keys, no accounts, and no content-derived logs.

## Checks

```sh
cargo fmt --check --manifest-path pigeon-relay/Cargo.toml
cargo clippy --manifest-path pigeon-relay/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path pigeon-relay/Cargo.toml
```

## Relay expectations

- Keep storage ephemeral unless the security model is updated first.
- Do not add authentication to publishing that would identify senders.
- Do not log mailbox addresses, ciphertext, signatures, nonces, or IP-derived
  identifiers beyond operationally necessary aggregate diagnostics.
- Preserve at-least-once delivery and explicit `ack` deletion semantics.
