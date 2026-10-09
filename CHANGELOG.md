# Changelog

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
