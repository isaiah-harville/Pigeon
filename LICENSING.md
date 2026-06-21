# Pigeon Licensing

Pigeon is a multi-license repository. There is no single repository-wide
license grant.

| Path | License | Intent |
| --- | --- | --- |
| `Pigeon/` | [Pigeon Source Available License](Pigeon/LICENSE) | Source-available iOS app code for transparency, review, local development, and security research. Not open source; commercial use, app redistribution, and App Store/TestFlight publication require permission. |
| `pigeon-core/` | [GNU AGPL-3.0-only](pigeon-core/LICENSE) | Reusable Rust messaging core (Olm via `vodozemac`). Open source and copyleft so modified versions offered to users stay source-available. |
| `pigeon-ffi/` | GNU AGPL-3.0-only (`license` field in `pigeon-ffi/Cargo.toml`) | UniFFI bridge for `pigeon-core` and `pigeon-mesh`; same copyleft terms as the crates it wraps. |
| `pigeon-mesh/` | [GNU AGPL-3.0-only](pigeon-mesh/LICENSE) | Reusable Rust mesh/transport crate (framing, fragmentation, flood routing, envelope). Open source and copyleft so modified versions offered to users stay source-available. |
| `pigeon-relay/` | [GNU AGPL-3.0-only](pigeon-relay/LICENSE) | Reusable relay server. Open source and copyleft, including AGPL network source availability for modified network services. |

Files outside those directories are covered by the nearest applicable license
notice when one exists. If a file has no applicable license notice, no additional
reuse permission is granted beyond what copyright law and the hosting platform's
terms require.

This summary is informational. The license files linked above are the
authoritative terms for their respective paths.
