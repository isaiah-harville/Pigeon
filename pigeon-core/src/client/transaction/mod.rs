mod checkpoint;
mod group_creation;
mod group_invite;
mod group_messaging;
mod group_policy;
mod group_recovery;
mod pairwise;

use checkpoint::{decode_checkpoint, encode_checkpoint};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::client::{
    ClientCommand, ClientOutput, ClientSnapshot, GroupInviteEnvelopeOutcome, GroupMessageOutcome,
};
use crate::group::{PigeonGroupPolicy, group_relay_challenge_transcript, relay_capability_id};
use crate::identity::PlatformAccount;
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::storage::StateStore;
use crate::wire::{PROTOCOL_VERSION, proto};

const GROUP_SECURITY_REJECTED_COORDINATOR_ENTRY_CODE: u32 = 2;

include!("mod_parts/execution.rs");
include!("mod_parts/snapshot.rs");
