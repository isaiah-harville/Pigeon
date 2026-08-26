// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Version-two JSON protocol for the isolated opaque group-message service.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::coordinator::protocol::{CandidateWire, ReceiptWire};
use crate::group::store::{CapabilityRegistration, GroupCapability, GroupRegistration, StoreError};

pub const GROUP_PROTOCOL_VERSION: u32 = 2;
pub const MAX_GROUP_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const GROUP_REGISTRATION_DOMAIN: &[u8] = b"pigeon.relay.group.registration.v1";
pub const GROUP_CHALLENGE_DOMAIN: &[u8] = b"pigeon.relay.group.challenge.v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CapabilityWire {
    pub public_key: String,
    pub can_append: bool,
    pub can_read: bool,
    pub can_control: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GroupClientMsg {
    Hello {
        min_protocol_version: u32,
        max_protocol_version: u32,
    },
    Register {
        coordination_id: String,
        capabilities: Vec<CapabilityWire>,
        signature: String,
    },
    Authenticate {
        coordination_id: String,
        capability_key: String,
    },
    Auth {
        signature: String,
    },
    Append {
        ciphertext: String,
    },
    Fetch {
        after_cursor: u64,
    },
    Advance {
        sequence: u64,
    },
    Rotate {
        old_public_key: String,
        replacement: CapabilityWire,
    },
    Revoke {
        public_key: String,
    },
    RegisterPush {
        token: String,
    },
    UnregisterPush {
        token: String,
    },
    CoordinatorKey,
    CoordinatorSubmit {
        claimed_base_epoch: u64,
        candidate: String,
    },
    CoordinatorFetch {
        after_sequence: u64,
    },
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GroupServerMsg {
    Compatible {
        protocol_version: u32,
        relay_version: String,
    },
    Incompatible {
        protocol_version: u32,
        relay_version: String,
    },
    Challenge {
        nonce: String,
    },
    Registered,
    Appended {
        sequence: u64,
    },
    Entries {
        entries: Vec<GroupEntryWire>,
    },
    Wake,
    Ok,
    Error {
        message: String,
    },
    CoordinatorKey {
        public_key: String,
    },
    CoordinatorReceipt {
        receipt: ReceiptWire,
    },
    CoordinatorCandidates {
        candidates: Vec<CandidateWire>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct GroupEntryWire {
    pub sequence: u64,
    pub ciphertext: String,
    pub timestamp: u64,
}

pub enum GroupProtocolGate {
    Reply(GroupServerMsg),
    Proceed(GroupClientMsg),
}

pub fn gate_group_message(message: GroupClientMsg, negotiated: &mut bool) -> GroupProtocolGate {
    match message {
        GroupClientMsg::Hello {
            min_protocol_version,
            max_protocol_version,
        } if !*negotiated => {
            if min_protocol_version <= GROUP_PROTOCOL_VERSION
                && max_protocol_version >= GROUP_PROTOCOL_VERSION
            {
                *negotiated = true;
                GroupProtocolGate::Reply(GroupServerMsg::Compatible {
                    protocol_version: GROUP_PROTOCOL_VERSION,
                    relay_version: env!("CARGO_PKG_VERSION").into(),
                })
            } else {
                GroupProtocolGate::Reply(GroupServerMsg::Incompatible {
                    protocol_version: GROUP_PROTOCOL_VERSION,
                    relay_version: env!("CARGO_PKG_VERSION").into(),
                })
            }
        }
        GroupClientMsg::Hello { .. } => GroupProtocolGate::Reply(GroupServerMsg::Error {
            message: "protocol already negotiated".into(),
        }),
        other if *negotiated => GroupProtocolGate::Proceed(other),
        _ => GroupProtocolGate::Reply(GroupServerMsg::Error {
            message: "protocol negotiation required".into(),
        }),
    }
}

pub fn verify_registration(
    coordination_id: &str,
    capabilities: &[CapabilityWire],
    signature: &str,
) -> Result<GroupRegistration, StoreError> {
    let coordination_id = decode_fixed(coordination_id)?;
    let capabilities = capabilities
        .iter()
        .map(decode_capability)
        .collect::<Result<Vec<_>, _>>()?;
    let controller = capabilities
        .iter()
        .find(|capability| capability.can_control)
        .ok_or(StoreError::InvalidRegistration)?;
    let signature = decode_signature(signature)?;
    let transcript = registration_transcript(coordination_id, &capabilities);
    VerifyingKey::from_bytes(&controller.public_key)
        .map_err(|_| StoreError::InvalidRegistration)?
        .verify_strict(&transcript, &signature)
        .map_err(|_| StoreError::Unauthorized)?;
    Ok(GroupRegistration {
        coordination_id,
        capabilities,
    })
}

pub fn verify_challenge(capability: &GroupCapability, nonce: &[u8; 32], signature: &str) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&capability.public_key) else {
        return false;
    };
    let Ok(signature) = decode_signature(signature) else {
        return false;
    };
    key.verify_strict(&challenge_transcript(capability, nonce), &signature)
        .is_ok()
}

pub fn registration_transcript(
    coordination_id: [u8; 32],
    capabilities: &[CapabilityRegistration],
) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(GROUP_REGISTRATION_DOMAIN.len() + 32 + 4 + capabilities.len() * 35);
    transcript.extend_from_slice(GROUP_REGISTRATION_DOMAIN);
    transcript.extend_from_slice(&coordination_id);
    transcript.extend_from_slice(&(capabilities.len() as u32).to_be_bytes());
    for capability in capabilities {
        transcript.extend_from_slice(&capability.public_key);
        transcript.push(capability.can_append.into());
        transcript.push(capability.can_read.into());
        transcript.push(capability.can_control.into());
    }
    transcript
}

pub fn challenge_transcript(capability: &GroupCapability, nonce: &[u8; 32]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(GROUP_CHALLENGE_DOMAIN.len() + 96);
    transcript.extend_from_slice(GROUP_CHALLENGE_DOMAIN);
    transcript.extend_from_slice(&capability.coordination_id);
    transcript.extend_from_slice(&capability.public_key);
    transcript.extend_from_slice(nonce);
    transcript
}

pub fn decode_capability(
    capability: &CapabilityWire,
) -> Result<CapabilityRegistration, StoreError> {
    let public_key = decode_fixed(&capability.public_key)?;
    VerifyingKey::from_bytes(&public_key).map_err(|_| StoreError::InvalidRegistration)?;
    Ok(CapabilityRegistration {
        public_key,
        can_append: capability.can_append,
        can_read: capability.can_read,
        can_control: capability.can_control,
    })
}

pub fn decode_group_capability(
    coordination_id: &str,
    public_key: &str,
) -> Result<GroupCapability, StoreError> {
    Ok(GroupCapability {
        coordination_id: decode_fixed(coordination_id)?,
        public_key: decode_fixed(public_key)?,
    })
}

pub fn decode_public_key(encoded: &str) -> Result<[u8; 32], StoreError> {
    decode_fixed(encoded)
}

fn decode_fixed(encoded: &str) -> Result<[u8; 32], StoreError> {
    let bytes = hex::decode(encoded).map_err(|_| StoreError::InvalidRegistration)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::InvalidRegistration)
}

fn decode_signature(encoded: &str) -> Result<Signature, StoreError> {
    let bytes = B64
        .decode(encoded)
        .map_err(|_| StoreError::InvalidRegistration)?;
    Signature::from_slice(&bytes).map_err(|_| StoreError::InvalidRegistration)
}
