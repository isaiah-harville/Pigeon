# Contributing to Pigeon

Pigeon is security-sensitive software. Contributions should be small, reviewable,
and honest about what is implemented versus what is only designed.

## Project sites

- Main site: [pigeonwire.app](https://pigeonwire.app/)
- Documentation: [docs.pigeonwire.app](https://docs.pigeonwire.app/)
- Support: [pigeonwire.app/support](https://pigeonwire.app/support/)
- Privacy policy: [pigeonwire.app/privacy-policy](https://pigeonwire.app/privacy-policy/)

## Before changing code

Read these first:

- [README.md](README.md)
- [CLAUDE.md](CLAUDE.md)
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)

For package-specific work, also read the package README and CONTRIBUTING file.

## Local checks

Run the narrowest checks that match your change:

```sh
cargo test --workspace
bash pigeon-ffi/build-xcframework.sh   # regenerate bindings + XCFramework
swift test --package-path Pigeon/PigeonFFI
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO
uv run --group docs mkdocs build --strict
```

Formatting and linting:

```sh
swiftlint lint --strict
swift-format lint --recursive --parallel Pigeon
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Security expectations

- Never log private keys, plaintext, message keys, root keys, chain keys, safety
  number seeds, raw Keychain values, or decrypted message bodies.
- Use CryptoKit or audited platform primitives. Do not implement cryptographic
  math in this repo.
- Keep wire formats deterministic and documented.
- Treat transport metadata as observable unless a document explicitly says it is
  protected.
- Preserve identity continuity. Identity resets and verification changes must be
  explicit and user-visible.

## Documentation expectations

Documentation is source, not decoration. Update docs and code comments in the
same PR as behavior changes when any of these change:

- transport behavior or relay semantics
- QR/contact-card wire format
- cryptographic protocol composition
- storage or Keychain behavior
- build, release, deployment, or contribution workflow

Build the docs locally with:

```sh
uv run --group docs mkdocs build --strict
```

Bring up the curated MkDocs site locally with:

```sh
uv run --group docs mkdocs serve
```

The published documentation is built from MkDocs, then Swift DocC and rustdoc
are generated under `public/api/`, and the combined output is deployed to GitHub
Pages.

## LLM and agent-assisted work

LLMs and coding agents are welcome here. They are useful for exploration,
mechanical edits, test scaffolding, and first drafts.

They are not a substitute for ownership. A ticket or pull request should not be
100% vibe-coded: the human submitter is responsible for reading the diff,
understanding security implications, running relevant checks, and correcting
stale comments or docs. For crypto, identity, transport, storage, or relay work,
include a short note in the PR explaining the invariant being preserved and what
you verified manually.

Do not paste secrets, private keys, user data, unreleased credentials, or
security-sensitive logs into an external LLM service.

## Pull request shape

Prefer PRs that do one thing:

- a bug fix with a focused test
- a small feature with docs updated
- a documentation-only clarification
- a mechanical cleanup that avoids behavior changes

Call out remaining limitations explicitly. Pigeon values clear caveats over
overconfident prose.
