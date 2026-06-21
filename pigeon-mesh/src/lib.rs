//! Pigeon's transport-agnostic mesh layer.
//!
//! This crate is the shared, platform-independent core of Pigeon's mesh: every
//! client (iOS today, others later) speaks the same wire format by linking it,
//! rather than re-implementing the framing per platform. It carries **opaque
//! bytes** and performs **no cryptography** — payloads are already ciphertext
//! when they reach here; the mesh only reads routing headers to deduplicate,
//! relay, fragment, and address.
//!
//! Three layers, each a deterministic fixed-width wire format:
//!
//! - [`packet`] — the [`MeshPacket`] envelope (`version ‖ ttl ‖ packetID ‖
//!   payload`), the [`SeenCache`] for duplicate suppression, and the
//!   [`MeshRouter`] flood-routing decision (deliver and/or relay).
//! - [`fragment`] — [`Fragment`]ing logical messages into BLE-sized pieces and
//!   [`Reassembler`]-ing them back, tolerant of reorder/duplication and bounded
//!   against memory exhaustion.
//! - [`envelope`] — the identity-addressed [`SessionEnvelope`] (`sender ‖
//!   recipient ‖ type ‖ payload`) routed inside a packet's payload.

pub mod envelope;
pub mod fragment;
pub mod packet;

pub use envelope::{EnvelopeError, EnvelopeType, SessionEnvelope};
pub use fragment::{Fragment, FragmentationError, Fragmenter, Reassembler};
pub use packet::{MeshError, MeshPacket, MeshRouter, Reception, SeenCache};
