# Pigeon Encryption Export Compliance Documentation

Effective date: June 16, 2026

## Short App Description

Pigeon is an offline-capable messaging app for iPhone. It lets users exchange
messages with verified contacts over Bluetooth mesh transport and over
user-configured federated relay servers when contacts are out of Bluetooth
range. The app is designed for private, low-infrastructure
communication: users pair by exchanging public identity information, verify
peers with safety numbers, and send end-to-end encrypted messages without
requiring a Pigeon account, phone number, or central messaging service.

## Purpose Of Encryption

Pigeon uses encryption and cryptographic authentication for:

- End-to-end message confidentiality and integrity between conversation
  participants.
- Peer identity verification and protection against impersonation.
- Forward secrecy and post-compromise recovery for conversations.
- Encrypted local storage of contacts and conversation state on the device.
- Authentication to optional relay mailboxes without revealing private keys.

Pigeon does not use encryption for digital rights management, payment
processing, VPN/tunneling, cryptocurrency, or general-purpose file encryption.

## Encryption Declaration

The app's `Info.plist` includes:

```xml
<key>ITSAppUsesNonExemptEncryption</key>
<false/>
```

This is set to `false` because Pigeon's use of standard, publicly documented
encryption is treated as exempt from Apple's export compliance documentation
requirement for the app's current distribution configuration.

## Algorithms And Standards

Pigeon uses standard, publicly known cryptographic algorithms. It does not
contain proprietary encryption algorithms.

Algorithms used by the iOS app include:

- X25519 / Curve25519 key agreement for Olm session establishment and the Double
  Ratchet's Diffie-Hellman steps.
- Ed25519 signatures for long-term device identity (the identity binding) and
  relay challenge authentication.
- SHA-256 and SHA-512 hashing for fingerprints and safety-number derivation.
- HKDF-SHA256 for Olm root/chain key derivation.
- HMAC-SHA256 for Olm message authentication and chain key advancement.
- AES-256-CBC for Olm message encryption (Encrypt-then-MAC with HMAC-SHA256).
- AES-256-GCM authenticated encryption for local encrypted storage.

These algorithms are standard algorithms accepted by international standards
communities or widely specified public cryptographic protocols. Pigeon does not
implement custom cryptographic primitives.

## Apple APIs And App Code

The pairwise messaging protocol (Olm: session establishment and the Double
Ratchet) is provided by the audited `vodozemac` Rust crate, linked into the app
through the `pigeon-core` / `PigeonFFI` XCFramework. The app itself uses Apple's
CryptoKit APIs for the remaining primitive operations: Ed25519 identity
signatures, SHA hashing for safety numbers, and AES-GCM for at-rest storage.

The app code composes these into:

- The identity binding: a long-term Ed25519 key signs Olm's Curve25519 identity
  key, so verifying a peer's safety number authenticates the channel.
- A small encrypted-storage wrapper (`SecretBox`) using AES-256-GCM.

Neither the app nor `pigeon-core` implements low-level cryptographic math such as
curve operations, block ciphers, hash compression functions, or polynomial
authentication; that math comes from CryptoKit and `vodozemac`'s vetted
dependencies.

## Key Management

Each device generates long-term identity key material locally. Private identity
material is stored on the device in the Apple Keychain. Private keys are not
uploaded to Pigeon infrastructure.

Conversation keys are derived during peer-to-peer session establishment and are
advanced by the Double Ratchet. Message keys are intended for one-time use.

Optional relay servers do not receive private keys and are designed to handle
only opaque ciphertext plus routing metadata.

## Network And Relay Behavior

Pigeon can operate without Pigeon-operated servers when peers communicate over
Bluetooth. If users configure relay endpoints, relays store and forward
end-to-end encrypted ciphertext addressed by public identity keys. Relays may
see network metadata such as IP addresses, timing, mailbox public keys, and
ciphertext sizes, but they are not designed to decrypt message contents.

## Export-Relevant Summary

- Encryption is a primary feature of the app.
- Encryption is used for secure messaging, authentication, and local data
  protection.
- The app uses standard public algorithms.
- The app does not contain proprietary encryption algorithms.
- The app does not provide a general-purpose encryption toolkit to users.
- The app does not expose private cryptographic keys to Pigeon servers.
- The app is a consumer messaging application, not a military, intelligence, or
  government-only product.

## Related Internal Documentation

Additional implementation detail is available in:

- `docs/SECURITY_MODEL.md`
- `pigeon-core/src/session.rs` (Olm session establishment + Double Ratchet)
- `pigeon-core/src/identity.rs` (Ed25519 identity binding)
- `pigeon-core/src/prekey.rs` (signed prekeys)
- `Pigeon/Pigeon/Core/Storage/SecretBox.swift` (at-rest AES-GCM)
