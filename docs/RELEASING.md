# Releases and versions

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

`pigeon-mesh` is stil being considered for an eventual crates.io publication. CI verifies its package on every relevant change. Publication remains manual until maintainers configure a crates.io trusted publisher and explicitly approve the first
release.

`pigeon-core` is also a useful public library, but it is not publishable yet:
its build consumes the canonical protobuf schema from the workspace-level
`proto/` directory, which a crates.io package cannot contain. `pigeon-ffi` is an
internal Apple build bridge rather than an independently released component;
Cargo requires its manifest version, but Pigeon does not tag or enforce that
version. `pigeon-relay` is distributed as a container. Both are explicitly
excluded from crates.io publication.
