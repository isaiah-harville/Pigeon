//! # pigeon-core
//!
//! Pairwise end-to-end-encrypted messaging for Pigeon, built on **Olm** via the
//! audited [`vodozemac`] crate. This is the Rust successor to the Swift
//! `PigeonCrypto` package: it replaces the hand-rolled Noise XX handshake,
//! signed-prekey X3DH, and clean-room Double Ratchet with Olm's audited
//! Account/Session — async-first session establishment plus the Double Ratchet
//! (forward secrecy, post-compromise security, out-of-order / skipped-message
//! tolerance). The ratchet math is vodozemac's; we no longer hand-roll it.
//!
//! ## What Pigeon keeps on top of Olm
//!
//! Olm sessions are authenticated by Curve25519 keys, but Olm does not, by
//! itself, tie a peer's Curve25519 identity key to a stable, human-verifiable
//! identity. Pigeon's trust model rests on a long-term **Ed25519 identity key**
//! (the safety-number root, verified out of band). pigeon-core therefore keeps
//! one piece of protocol trust: the identity key **signs Olm's Curve25519
//! identity key** (the *identity binding*, [`IdentityBundle`]) and every
//! published prekey ([`PrekeyBundle`]). Verifying a peer's safety number thus
//! authenticates the whole channel — the same invariant the Swift
//! `IdentityBundle` enforced. The Ed25519 identity is independent of the Olm
//! account, so re-pickling or rotating Olm keys never churns safety numbers.
//!
//! ## Lifecycle
//!
//! 1. Each device owns one [`Account`] (Ed25519 identity + Olm account).
//! 2. A recipient publishes a [`PrekeyBundle`] (signed-prekey and/or one-time
//!    prekeys) ahead of time, via QR / mesh gossip / relay.
//! 3. An initiator calls [`Session::establish_outbound`] against a verified
//!    bundle, producing the session and an [`Initiation`] (its identity bundle +
//!    the first Olm pre-key message) to send.
//! 4. The recipient calls [`Session::establish_inbound`] when it next comes
//!    online, recovering the session and the first plaintext.
//! 5. Both ends exchange traffic with [`Session::encrypt`] / [`Session::decrypt`].
//!
//! Wire types are encoded with the shared `pigeon.wire.v1` Protocol Buffer
//! schemas in `proto/pigeon/wire/v1/`.

#![forbid(unsafe_code)]

mod client;
mod error;
mod group;
mod identity;
mod storage;
mod wire;

pub use client::{AppEvent, ClientCommand, ClientOutput, OutboundItem, PigeonClient};
pub use error::Error;
pub use group::{
    Actor, AuthenticatedGroupMessage, BufferDisposition, CanonicalCandidate, CoordinatorBinding,
    CoordinatorChain, CoordinatorChainError, CoordinatorReceipt, DeliveryLedger, EpochBuffer,
    GroupAction, GroupApplication, GroupCiphertext, GroupCreationConfig, GroupDeliveryState,
    GroupEngine, GroupId, GroupMessageId, GroupRelayCapability, GroupRelayRegistration,
    PendingMutation, PigeonGroupPolicy, PolicyError, PolicyEvent, PolicyEventKind,
    coordinator_receipt_transcript, select_canonical_candidate, validate_transition,
};
pub use identity::{
    Account, GroupJoinMaterial, GroupJoinRequest, GroupMemberKeys, IdentityBundle, IdentityError,
    IdentityKeypair, IdentityPurpose, Initiation, KeyPackagePool, MlsIdentityBinding, PrekeyBundle,
    ReservedKeyPackage, SecureIdentity, Session, decode_olm_message, encode_olm_message,
};
pub use storage::{
    MemoryStateStore, SealedCheckpoint, StateStore, StorageError, TransactionalOpenMlsStorage,
};
pub use wire::proto as wire_proto;
pub use wire::{
    MAX_CLIENT_COMMAND_BYTES, MAX_FUTURE_EPOCH_BUFFER_BYTES, MAX_FUTURE_EPOCHS,
    MAX_GROUP_APPLICATION_BYTES, MAX_GROUP_MEMBERS, MAX_MLS_OBJECT_BYTES,
    MAX_PENDING_OUTBOUND_ENTRIES, MAX_PROPOSAL_CANDIDATES, decode_client_command,
};

/// The Olm message type that crosses pigeon-core's API surface. Re-exported so
/// callers need not depend on `vodozemac` directly.
pub use vodozemac::olm::OlmMessage;
