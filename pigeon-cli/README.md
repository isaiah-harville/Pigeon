# pigeon-cli

`pigeon` is a terminal client for Pigeon. It sends and receives end-to-end-encrypted
direct messages over Pigeon relays and interoperates with the iPhone app. It uses the
same messaging core (`pigeon-core`, Olm via the audited `vodozemac` crate), the same
contact cards and safety numbers, and the same relay mailbox protocol.

It does direct messages only. The Bluetooth/Wi-Fi mesh and MLS group chats stay on the
phone for now.

## Build

```sh
cargo build --release -p pigeon-cli      # produces target/release/pigeon
```

Pure Rust with rustls, so it builds on macOS, Linux, and Windows without system TLS
libraries.

## Use

```sh
pigeon init --name "Ada"                 # create an identity; asks for a passphrase
pigeon card                              # your contact link, to send to someone
pigeon add 'https://pigeonwire.app/contact#card=…'   # add someone from their link
pigeon send ada "hello"                  # one message, waits for the relay receipt
pigeon                                   # interactive chat (type /help)
pigeon listen                            # print messages as they arrive
pigeon accept bob                        # accept an incoming message request
pigeon safety bob                        # compare this number in person
```

Adding someone from a link sends a **message request**: your first message goes out
with your card, and you can send more once they accept. If you both added each other
in person, use `pigeon add --mutual <link>` to skip that step.

By default you receive on `wss://relay.pigeonwire.app/ws`; use `--relay` on `init` (or
`pigeon relays <url>…`) to pick your own. Share a fresh `pigeon card` after changing
relays.

## Storage and security

- Everything lives in `~/.pigeon` (override with `--home` or `PIGEON_HOME`), owner-only.
- The identity seed, the core checkpoint (Olm account and ratchets), and message
  history are sealed with XChaCha20-Poly1305 under a key derived from your
  passphrase with Argon2id (64 MiB, 3 passes). Each file binds its purpose as
  associated data, and writes are atomic and fsynced.
- A lock file stops two `pigeon` processes from using one vault at once, which
  would fork the ratchet state.
- `PIGEON_PASSPHRASE` exists for scripts and tests. Interactively, prefer the prompt
  so the passphrase stays out of your shell history and environment.
- Incoming names and messages have control characters and bidi overrides stripped
  before they reach your terminal.
- A relay message is acked only after the core has durably applied it. Outbound
  messages stay sealed in the vault until a relay confirms storage.

Not audited; see `docs/SECURITY_MODEL.md` for the overall threat model.
