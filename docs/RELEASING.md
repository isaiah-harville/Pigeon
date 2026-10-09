# Releases and versions

The iOS target deliberately omits `ITSAppUsesNonExemptEncryption`. Before each
App Store or TestFlight submission, complete App Store Connect's encryption
questionnaire for the actual build and distribution regions, then attach any
documentation Apple requests. The project does not assert an exemption in its
build settings. See [Apple's export compliance overview](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance/).

Pigeon versions each deployable component independently. Versions come from
component manifests and are changed in normal reviewed pull requests:

| Component | Version source |
| --- | --- |
| iOS app | `Pigeon/VERSION` and app `MARKETING_VERSION` |
| Website | `site/VERSION` |
| Relay | `pigeon-relay/Cargo.toml` |
| Messaging core | `pigeon-core/Cargo.toml` |
| Mesh library | `pigeon-mesh/Cargo.toml` |

All versions use semantic versioning. The release-version workflow
requires a version bump whenever component code, protocol, packaging, or
deployment files change. Documentation-only changes do not require a bump.

Merges to `main` publish the `latest` website and relay container images. When
the website or relay's declared version changes, that merge also publishes the
immutable `vX.Y.Z` image tag. Git tags do not trigger releases.

Release workflows do not upload custom source archives. GitHub may display its
automatic source-code zip and tar links for a Git tag, but Pigeon does not build,
store, or attach duplicate source distributions.

## Rust crates

`pigeon-mesh` is still being considered for an eventual crates.io publication.
CI verifies its package on every relevant change. Publication remains manual
until maintainers configure a crates.io trusted publisher and explicitly approve
the first release.

`pigeon-core` is also a useful public library, but it is not publishable yet:
its build consumes the canonical protobuf schema from the workspace-level
`proto/` directory, which a crates.io package cannot contain. `pigeon-ffi` is an
internal Apple build bridge rather than an independently released component;
Cargo requires its manifest version, but Pigeon does not tag or enforce that
version. `pigeon-relay` is distributed as a container. Both are explicitly
excluded from crates.io publication.

## iOS 1.4 release gates

Before distributing the group-chat and device-move build, record a passing
reviewed CI run and complete these checks on two physical iPhones. Simulators
cannot establish the required BLE and Multipeer behavior or validate locked
background delivery.

- Create a group, join through public and private invites, send and receive
  across BLE and relay links, remove a member, rotate the group capability,
  and verify the removed member cannot send or receive.
- Lock a running recipient and verify messages are durably recorded. Relaunch
  the app cold while locked, then unlock and verify relay redelivery without a
  lost or duplicated message.
- Move an identity and live group state between unlocked phones. Confirm the
  comparison code on both screens, verify the old phone rotates identity, and
  verify the new phone retains group membership without saved message history.
- Interrupt the move before staging, after staging, during source retirement,
  and after source retirement but before destination activation. Reopen both
  phones and verify either a safe resume or an explicit recovery state.
- Reinstall while a Keychain identity survives. Verify Pigeon requires an
  explicit fresh start and rotates the identity; it must not silently reuse a
  key with missing encrypted session state.

An independent security review of Pigeon's integration remains required before
claiming the app is audited or production-secure. See `SECURITY_MODEL.md`.
