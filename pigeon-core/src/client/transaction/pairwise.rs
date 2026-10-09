use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;

use super::{PigeonClient, pairwise_account};
use crate::client::{ClientOutput, OutboundItem};
use crate::identity::{
    IdentityBundle, Initiation, PlatformAccount, PlatformSession, PrekeyBundle, decode_olm_message,
    encode_olm_message,
};
use crate::storage::StateStore;
use crate::wire::{PROTOCOL_VERSION, proto};
use crate::{Error, SecureIdentity};

/// Our own outbound session plus the peer's crossing initiation.
const MAX_PAIRWISE_SESSIONS_PER_PEER: usize = 2;

include!("pairwise_parts/outbound.rs");
include!("pairwise_parts/inbound.rs");
