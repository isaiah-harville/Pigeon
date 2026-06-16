# Source Map

This page maps the published docs back to the source tree. The MkDocs site also
includes component READMEs and source maps from each subproject through the
monorepo plugin.

## App

- `Pigeon/Pigeon.xcodeproj` — iOS app project, scheme `Pigeon`.
- `Pigeon/Pigeon/App/` — app entry point.
- `Pigeon/Pigeon/Core/Identity/` — identity keys, Keychain persistence,
  fingerprints, and safety numbers.
- `Pigeon/Pigeon/Core/Contacts/` — contacts and QR contact-card encoding.
- `Pigeon/Pigeon/Core/Session/` — session coordinator, handshakes, messaging,
  conversations, and UI-facing state.
- `Pigeon/Pigeon/Core/Transport/` — BLE, relay, composite transport, relay
  settings, and relay pings.
- `Pigeon/Pigeon/Core/Mesh/` — app-facing mesh service over pluggable transports.
- `Pigeon/Pigeon/Core/Storage/` — encrypted local persistence and vault key.
- `Pigeon/Pigeon/Features/` — SwiftUI surfaces.

## Packages

- `PigeonCrypto/` — clean-room Swift package for Noise, Double Ratchet, identity
  bundles, and encrypted session composition.
- `PigeonMesh/` — dependency-free Swift package for packet framing,
  fragmentation, session envelopes, TTL, and duplicate suppression.
- `PigeonRelay/` — Rust zero-knowledge relay server.

## Infrastructure

- `.github/workflows/swift.yml` — Swift lint, package tests, and app build.
- `.github/workflows/relay.yml` — relay checks and GHCR image publishing.
- `.github/workflows/docs.yml` — MkDocs GitHub Pages deployment.
- `.github/workflows/website.yml` — static marketing/support site image.
