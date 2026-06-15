# Pigeon Encryption Export Compliance Documentation

Effective date: June 16, 2026

## Short App Description

Pigeon is an offline-first messaging app for iPhone. It lets users exchange
messages with verified contacts over Bluetooth mesh transport, and optionally
over user-configured relay servers when contacts are out of Bluetooth range.
The app is designed for private, tactical, low-infrastructure communication:
users pair by exchanging public identity information, verify peers with safety
numbers, and send end-to-end encrypted messages without requiring a Pigeon
account, phone number, or central messaging service.

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
<true/>
```

This is set to `true` because Pigeon uses encryption as a core feature of a
private messaging product, including standard cryptographic protocols composed
by the app in addition to direct use of Apple's operating-system cryptographic
APIs.

## Algorithms And Standards

Pigeon uses standard, publicly known cryptographic algorithms. It does not
contain proprietary encryption algorithms.

Algorithms used by the iOS app include:

- X25519 / Curve25519 key agreement for session establishment and ratchet steps.
- Ed25519 signatures for long-term device identity and relay challenge
  authentication.
- SHA-256 and SHA-512 hashing for fingerprints, transcripts, and safety-number
  derivation.
- HKDF-SHA256 for key derivation.
- HMAC-SHA256 for Double Ratchet chain key derivation.
- AES-256-GCM authenticated encryption for message encryption and local
  encrypted storage.
- ChaCha20-Poly1305 authenticated encryption inside the Noise handshake.

These algorithms are standard algorithms accepted by international standards
communities or widely specified public cryptographic protocols. Pigeon does not
implement custom cryptographic primitives.

## Apple APIs And App Code

Pigeon primarily uses Apple's CryptoKit APIs for primitive cryptographic
operations, including Curve25519 keys, Ed25519 signatures, SHA hashing, HKDF,
HMAC, AES-GCM, and ChaChaPoly.

The Pigeon app code composes these primitives into messaging protocols:

- A clean-room implementation of the Noise XX handshake pattern using the
  `Noise_XX_25519_ChaChaPoly_SHA256` construction.
- A clean-room implementation of the Signal Double Ratchet construction.
- A small encrypted-storage wrapper using AES-GCM.

The app does not implement low-level cryptographic math such as curve
operations, block ciphers, hash compression functions, or polynomial
authentication.

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
- `PigeonCrypto/Sources/PigeonCrypto/NoiseHandshake.swift`
- `PigeonCrypto/Sources/PigeonCrypto/DoubleRatchet.swift`
- `PigeonCrypto/Sources/PigeonCrypto/Primitives.swift`
- `PigeonCrypto/Sources/PigeonCrypto/SecretBox.swift`
