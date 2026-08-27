//! Authenticated Pigeon policy layered on top of MLS protocol validity.

mod action;
mod buffer;
mod coordinator;
mod delivery;
mod engine;
mod id;
mod message;
mod pending;
mod policy;

pub use action::{Actor, GroupAction, PolicyEvent, PolicyEventKind};
pub use buffer::{BufferDisposition, EpochBuffer};
pub use coordinator::{
    CanonicalCandidate, CoordinatorBinding, CoordinatorChain, CoordinatorChainError,
    CoordinatorReceipt, coordinator_receipt_transcript, select_canonical_candidate,
};
pub use delivery::{DeliveryLedger, GroupDeliveryState};
pub(crate) use engine::GroupCreationConfig;
pub use engine::GroupEngine;
pub use id::GroupId;
pub use message::{AuthenticatedGroupMessage, GroupApplication, GroupCiphertext, GroupMessageId};
pub use pending::PendingMutation;
pub use policy::{PigeonGroupPolicy, PolicyError, validate_transition};
