use core::fmt;

use ed25519_dalek::VerifyingKey;
use prost::Message;
use sha2::{Digest, Sha256};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use super::{
    CoordinatorBinding, GroupAction, GroupId, PolicyEvent, PolicyEventKind, RecoveryCertificate,
};
use crate::identity::GroupMemberKeys;
use crate::wire::{
    MAX_GROUP_MEMBERS, MAX_GROUP_NAME_BYTES, MAX_GROUP_NAME_SCALARS, MAX_MLS_OBJECT_BYTES, proto,
};

const PROTOCOL_VERSION: u32 = 1;
const POLICY_VERSION: u32 = 2;
const MIN_GROUP_MEMBERS: usize = 1;

include!("policy_parts/state.rs");
include!("policy_parts/transitions.rs");
