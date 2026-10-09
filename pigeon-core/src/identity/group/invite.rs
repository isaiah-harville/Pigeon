use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use vodozemac::olm::{Account as OlmAccount, AccountPickle, OlmMessage};

use super::super::{IdentityPurpose, SecureIdentity};
use super::material::GroupJoinMaterial;
use super::reply::{GroupInviteReplyStatus, seal_reply};
use super::request::GroupJoinRequest;
use crate::Error;
use crate::group::GroupId;
use crate::identity::{decode_olm_message, encode_olm_message};
use crate::wire::{MAX_RELAY_URL_BYTES, proto};

const TICKET_VERSION: u32 = 1;
const INTENT_VERSION: u32 = 1;
const MAX_TICKET_BYTES: usize = 4096;
const MAX_INTENT_BYTES: usize = 512;
const INTENT_DOMAIN: &[u8] = b"pigeon.identity.group-invite-intent.v1";
const MAX_CIPHERTEXT_BYTES: usize = 8192;
const MAX_INBOX_STATE_BYTES: usize = 256 * 1024;
const MAX_CONSUMED_REQUESTS: usize = 1024;

include!("invite_parts/inbox.rs");
include!("invite_parts/ticket.rs");
