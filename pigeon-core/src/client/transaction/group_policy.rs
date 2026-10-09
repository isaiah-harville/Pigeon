use prost::Message;

use super::PigeonClient;
use crate::Error;
use crate::client::{AppEvent, ClientOutput, OutboundItem};
use crate::group::{
    CoordinatorChain, CoordinatorChainError, CoordinatorReceipt, GroupAction, GroupApplication,
    GroupEngine, GroupMutationCandidate, GroupRelayControl, PigeonGroupPolicy, PolicyEvent,
    PolicyEventKind, RecoveryCertificate, RecoveryControlKind, RecoveryProposal,
    relay_capability_id,
};
use crate::identity::{GroupJoinMaterial, GroupJoinRequest, IdentityPurpose, SecureIdentity};
use crate::storage::{StateStore, TransactionalOpenMlsStorage};
use crate::wire::{PROTOCOL_VERSION, proto};

const GROUP_SECURITY_COORDINATOR_FORK_CODE: u32 = 1;

include!("group_policy_parts/coordinator.rs");
include!("group_policy_parts/membership.rs");
