# OpenMLS Dependency Review

## Decision

Pigeon 1.4 uses the stable OpenMLS 0.9.0 crate family for RFC 9420 group
messaging. The selected cipher suite is
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.

Exact production dependencies:

| Crate | Version | Default features |
| --- | --- | --- |
| `openmls` | 0.9.0 | disabled |
| `openmls_rust_crypto` | 0.6.0 | disabled |
| `openmls_traits` | 0.6.0 | disabled |
| `openmls_basic_credential` | 0.6.0 | disabled |
| `tls_codec` | 0.5.0 | disabled; `derive`, `mls`, `serde`, and `std` enabled |

OpenMLS and its RustCrypto provider require Rust 1.91.0. Pigeon's development
toolchain is Rust 1.96.0.

## Forbidden release features

Pigeon release builds must not enable OpenMLS `content-debug`, `crypto-debug`,
`test-utils`, `extensions-draft`, `extensions-draft-test-dependencies`,
`targeted-messages-draft`, `virtual-clients-draft`, `all-ciphersuites`, or
`unchecked-conversions`.

## Release gates

- `cargo tree -e features` must show none of the forbidden features.
- `cargo audit` and `cargo deny check advisories licenses bans sources` must
  report no reachable unsuppressed security advisory in the selected OpenMLS,
  HPKE, signature, AEAD, or storage dependency graph.
- The MLS create, Welcome/join, application-message, reload, secret-deletion,
  and persistence-failure tests must pass.
- `pigeon-core` and `pigeon-ffi` must build for `aarch64-apple-ios`,
  `aarch64-apple-ios-sim`, and `aarch64-apple-darwin`.
- OpenMLS storage mutations and deletions must participate in Pigeon's
  persistence-before-output transaction.
- The dependency and integration must receive external security review before
  Pigeon claims audit readiness. Passing these gates is not an independent
  audit.

## Upstream security baseline

The review includes the published OpenMLS advisories for improper secret-tree
persistence and improper tag validation. Pigeon does not allow an advisory
suppression to substitute for a patched dependency. Any newly reported
reachable advisory blocks the 1.4 release until a patched exact version is
available and the full MLS test matrix passes again.

The stable 0.9.0 RustCrypto graph currently includes `proc-macro-error2` 2.0.1
through `hax-lib` and libcrux SHA-3. RustSec marks that proc-macro unmaintained
but does not report a vulnerability or unsoundness. It is used at compile time,
is not a direct Pigeon dependency, and remains visible as a `cargo audit` and
`cargo deny` warning. Pigeon must remove it when the OpenMLS/HPKE graph provides
a maintained replacement; any security-impacting advisory remains a release
blocker.

## Integration verification

The initial 0.9.0 integration was verified on 2026-08-25 with:

- a real two-member OpenMLS create, add, Welcome/join, encrypt, and decrypt
  smoke test using the selected cipher suite;
- the complete `pigeon-core` and `pigeon-ffi` Rust test suites;
- warning-free `pigeon-core` Clippy checks;
- `pigeon-core` and `pigeon-ffi` checks for `aarch64-apple-ios`,
  `aarch64-apple-ios-sim`, and `aarch64-apple-darwin`; and
- the full `cargo deny` advisory, license, ban, and source policy.

This verifies dependency compatibility only. The stateful MLS integration and
its persistence/recovery tests remain release gates.

Upstream references:

- <https://github.com/openmls/openmls/security>
- <https://github.com/openmls/openmls/blob/main/CHANGELOG.md>
- <https://github.com/openmls/openmls>
