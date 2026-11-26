# Changelog

## [1.5.1] - 2026-11-26 (beta)

### Added

- A [Terminal Client guide](docs/terminal-client.md) covers installing `pigeon`, creating an identity, exchanging contact links with the app, chatting, verifying safety numbers, choosing relays, backups, and troubleshooting.

### Fixed

- The `pigeon` terminal client can connect to relays when it is built or installed on its own. Before, `cargo install --path pigeon-cli` produced a binary with no TLS crypto backend that crashed on its first `wss://` connection.
- Push wake-ups work on relays that supply their APNs key inline. The relay reads the key from `PIGEON_APNS_KEY_PEM` as well as from a file at `PIGEON_APNS_KEY_PATH`, and names any missing APNs variable at startup. Before, an inline key was ignored and push was silently off, so a locked phone was never woken to collect its messages.

### Changed

- Pigeon builds with Rust 1.100. The relay image (0.5.3) uses the Rust 1.100.0 toolchain, and `pigeon-core` (0.2.3) no longer ships a dependency that only its tests use. The terminal client (0.1.2) needs Rust 1.89 or newer.
- The documentation no longer describes relay direct-message mailboxes as memory-only; they are stored durably, as in 1.5.0.

[1.5.1]: https://github.com/isaiah-harville/Pigeon/compare/v1.5.0...v1.5.1

## [1.5.0] - 2026-11-25 (beta)

### Added

- `pigeon`, a terminal client for any machine (`pigeon-cli/`). It exchanges end-to-end-encrypted direct messages with the iPhone app over relays: contact links, message requests, delivery receipts, and safety numbers. Its identity and history are sealed under a passphrase.
- Messages keep reaching a locked iPhone that is not running Pigeon. On each push, a notification service extension moves the still-encrypted messages from the relay into the phone, so they no longer depend on the relay holding them until you open the app. They are decrypted only after you unlock.

### Fixed

- Creating a group no longer gets stuck on "Registering with relay". Authenticating to the group relay re-entered the relay connection while it was being updated, which crashed the app or kept the registration retrying forever.
- Relays keep stored direct messages across a restart. Before, a relay restart lost every message waiting for a phone that was offline or locked, even though the sender had already been told it was stored.
- A phone coming back online after a long time receives every waiting message at once. Before, it received at most 256 and the rest waited for an unrelated reconnect.
- One direct message the relay refuses no longer holds up every message queued behind it. Sends go out several at a time, a refused one retries on its own schedule, and a stalled relay connection is noticed and replaced.
- Relay frames leave in the order they were sent.
- A running app that locks before its group relay first connects can still authenticate to that relay.
- Long chats scroll and render smoothly. New messages no longer pull you to the bottom while you read older history, the send button meets the 44-point touch target and has a VoiceOver label, blank messages can't be sent, and the **+** button no longer covers the last chat.
- A new chat opens even when its first message was lost or rejected: any later pre-key message from the sender establishes the session, and a replayed pre-key message can no longer open a second session.
- A message request to someone who already added you opens the chat when they reply, instead of staying stuck as a pending request on both phones.
- Scanning someone in person who already sent you a message request accepts the request. Before, the chat looked open but every message you sent was refused.
- A direct message that can never be opened (a bad signature, malformed bytes, a replay, or a stranger with no contact card) is released from the relay instead of being redelivered until it expires. Before, anyone with your public key could fill your relay mailbox with junk and block real messages for up to 30 days.
- Removing a contact and adding them again no longer leaves both of you unable to message each other. The next message from the side that re-added opens a fresh session. Old opening messages can't be replayed to bring back a dropped session, including after you remove and re-add someone.

### Security

- The relay (0.5.1) updates rustls to 0.23.46, rustls-webpki to 0.103.16, webpki-roots to 1.0.10, and tokio to 1.53.3, and moves to rusqlite 0.41, whose bundled SQLite fixes a known vulnerability. The website image (0.2.1) moves from the unmaintained nginx 1.27 base to nginx 1.30.

[1.5.0]: https://github.com/isaiah-harville/Pigeon/compare/v1.4.1...v1.5.0

## [1.4.1] - 2026-10-09 (beta)

### Added

- MLS group chats with shareable public and private invite links, group member and admin controls, relay delivery, and optional local mesh delivery.
- Group relay recovery when the original coordinator is unavailable, with authenticated coordinator receipts and durable client and relay state.
- Owner-confirmed identity move between nearby iPhones. The move transfers identity keys, active pairwise and group state, and group registrations. Saved message history is not transferred; the old phone erases its copy during retirement.
- A pinned **+** menu for New Chat, New Group, and Join Group. The top-right Contacts button opens the contacts list and its QR add-contact action.

### Changed

- Direct-chat protocol state is owned and checkpointed by `pigeon-core`; the Swift app receives typed events and opaque ciphertext through UniFFI.
- Group and pairwise relay paths retry unconfirmed work and preserve durable receive state before acknowledging delivery.
- Startup requires an explicit fresh start when a surviving Keychain identity has lost its local encrypted session state.

### Beta status

- The physical two-iPhone group, locked-delivery, and interrupted-move matrix in [release validation](docs/RELEASING.md) has not been completed for this beta.
- Pigeon has not received an independent security audit. This beta is not a production-secure release.

[1.4.1]: https://github.com/isaiah-harville/Pigeon/compare/v1.3.0...v1.4.1
