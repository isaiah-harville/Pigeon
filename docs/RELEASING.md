# Releases and versions

Pigeon versions each deployable component independently. Release tags are
component-prefixed and must match the version declared in the tagged commit:

| Component | Version source | Release tag |
| --- | --- | --- |
| iOS app | `Pigeon/VERSION` and app `MARKETING_VERSION` | `ios-v1.1.0` |
| Website | `site/VERSION` | `website-v1.1.0` |
| Relay | `pigeon-relay/Cargo.toml` | `relay-v0.1.1` |
| Messaging core | `pigeon-core/Cargo.toml` | `pigeon-core-v0.1.1` |
| Mesh library | `pigeon-mesh/Cargo.toml` | `pigeon-mesh-v0.1.1` |

All versions use semantic versioning. Bump the component's version in a normal
reviewed pull request before creating its tag. The release-version workflow
requires a version bump whenever component code, protocol, packaging, or
deployment files change. It also rejects a tag whose version does not exactly
match its declared source. Documentation-only changes do not require a bump.

Merges to `main` publish the `latest` website and relay container images.
`website-vX.Y.Z` and `relay-vX.Y.Z` publish the corresponding `vX.Y.Z` image tag
without moving `latest`.

## Rust crates

`pigeon-mesh` is stil being considered for an eventual crates.io publication. CI verifies its package on every relevant change. Publication remains manual until maintainers configure a crates.io trusted publisher and explicitly approve the first
release.

`pigeon-core` is also a useful public library, but it is not publishable yet:
its build consumes the canonical protobuf schema from the workspace-level
`proto/` directory, which a crates.io package cannot contain. `pigeon-ffi` is an
internal Apple build bridge rather than an independently released component;
Cargo requires its manifest version, but Pigeon does not tag or enforce that
version. `pigeon-relay` is distributed as a container. Both are explicitly
excluded from crates.io publication.
