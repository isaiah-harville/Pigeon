use sha2::{Digest, Sha256};

use super::PigeonClient;
use crate::Error;
use crate::client::{ClientOutput, OutboundItem};
use crate::group::{GroupId, PigeonGroupPolicy};
use crate::identity::{
    GroupInviteInbox, GroupInviteIntent, GroupInviteMode, GroupInviteReplyInbox,
    GroupInviteReplyStatus, GroupInviteTicket, GroupJoinMaterial, GroupJoinRequest,
    IdentityPurpose, SecureIdentity,
};
use crate::storage::{StateStore, TransactionalOpenMlsStorage};
use crate::wire::{MAX_GROUP_MEMBERS, proto};

const MAX_ACTIVE_INVITES: usize = 16;
const MAX_INVITE_JOINS: usize = 64;
const MAX_REQUESTS_PER_INVITE: usize = 128;
const MAX_INVITE_LIFETIME_MS: i64 = 30 * 24 * 60 * 60 * 1000;

include!("group_invite_parts/inbox.rs");
include!("group_invite_parts/replies.rs");
