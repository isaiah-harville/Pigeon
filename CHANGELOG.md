# Changelog

## [1.5.0] - Unreleased

### Fixed

- A new chat opens even when its first message was lost or rejected: any later pre-key message from the sender establishes the session, and a replayed pre-key message can no longer open a second session.
- A message request to someone who already added you opens the chat when they reply, instead of staying stuck as a pending request on both phones.
- Scanning someone in person who already sent you a message request accepts the request. Before, the chat looked open but every message you sent was refused.
- A direct message that can never be opened (a bad signature, malformed bytes, a replay, or a stranger with no contact card) is released from the relay instead of being redelivered until it expires. Before, anyone with your public key could fill your relay mailbox with junk and block real messages for up to 30 days.
- Removing a contact and adding them again no longer leaves both of you unable to message each other. The next message from the side that re-added opens a fresh session. Old opening messages can't be replayed to bring back a dropped session, including after you remove and re-add someone.

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
