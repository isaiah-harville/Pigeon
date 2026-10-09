use prost::Message;
use sha2::{Digest, Sha256};

use super::PigeonClient;
use super::checkpoint::{apply_delivery_acknowledgement, decode_message_id, encode_message_id};

use crate::Error;
use crate::client::{AppEvent, ClientOutput, OutboundItem};
use crate::group::{
    AcknowledgedMessage, GroupApplication, GroupEngine, GroupMessageId, PigeonGroupPolicy,
    RecoveryControlKind,
};
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::storage::{StateStore, TransactionalOpenMlsStorage};
use crate::wire::{
    MAX_FUTURE_EPOCH_BUFFER_BYTES, MAX_FUTURE_EPOCHS, MAX_GROUP_ACKNOWLEDGEMENT_BATCH,
    MAX_PENDING_OUTBOUND_ENTRIES, PROTOCOL_VERSION, proto,
};

const MAX_BUFFERED_GROUP_MESSAGES: usize = 64;

include!("group_messaging_parts/messages.rs");
include!("group_messaging_parts/acknowledgements.rs");
