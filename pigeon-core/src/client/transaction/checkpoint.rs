use prost::Message;
use sha2::{Digest, Sha256};

use crate::Error;
use crate::group::{CoordinatorChain, GroupEngine, GroupId};
use crate::storage::{SealedCheckpoint, StorageError};
use crate::wire::{PROTOCOL_VERSION, proto};

pub(super) fn encode_message_id(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(super) fn decode_message_id(encoded: &str) -> Result<crate::GroupMessageId, Error> {
    if encoded.len() != 32 {
        return Err(Error::MalformedBundle);
    }
    let mut bytes = [0_u8; 16];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(crate::GroupMessageId::from_bytes(bytes))
}

fn hex_nibble(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::MalformedBundle),
    }
}

pub(super) fn stored_group(engine: &GroupEngine) -> proto::StoredGroup {
    let policy = engine.policy();
    proto::StoredGroup {
        group_id: engine.group_id().as_bytes().to_vec(),
        owner_identity: policy.owner().to_vec(),
        name: policy.name().to_owned(),
        member_identities: policy
            .members()
            .iter()
            .map(|identity| identity.to_vec())
            .collect(),
        relay_url: policy.relay_url().to_owned(),
        mesh_enabled: policy.mesh_enabled(),
        epoch: engine.epoch(),
        policy_revision: policy.revision(),
        policy: policy.encode(),
        coordinator_chain: CoordinatorChain::new(
            policy.coordination_id(),
            policy.coordinator_public_key(),
        )
        .encode(),
    }
}

pub(super) fn apply_delivery_acknowledgement(
    candidate: &mut proto::ClientCheckpoint,
    group_id: GroupId,
    authenticated_sender: [u8; 32],
    original_sender: [u8; 32],
    message_id: crate::GroupMessageId,
) -> Result<Option<(proto::GroupDeliveryState, u32, u32)>, Error> {
    let ledger = candidate
        .delivery_ledgers
        .iter_mut()
        .find(|ledger| {
            ledger.group_id.as_slice() == group_id.as_bytes()
                && ledger.message_id.as_slice() == message_id.as_bytes()
        })
        .ok_or(Error::InvalidKey)?;
    if ledger.original_sender_identity.as_slice() != original_sender
        || !ledger
            .intended_identities
            .iter()
            .any(|identity| identity.as_slice() == authenticated_sender)
        || ledger.terminal_state != proto::GroupDeliveryState::Unspecified as i32
    {
        return Err(Error::InvalidSignature);
    }
    if ledger
        .acknowledged_identities
        .iter()
        .any(|identity| identity.as_slice() == authenticated_sender)
    {
        return Ok(None);
    }
    ledger
        .acknowledged_identities
        .push(authenticated_sender.to_vec());
    let delivered =
        u32::try_from(ledger.acknowledged_identities.len()).map_err(|_| Error::Serialization)?;
    let intended =
        u32::try_from(ledger.intended_identities.len()).map_err(|_| Error::Serialization)?;
    let state = if delivered == intended {
        proto::GroupDeliveryState::Delivered
    } else {
        proto::GroupDeliveryState::DeliveredTo
    };
    Ok(Some((state, delivered, intended)))
}

pub(super) fn encode_checkpoint(state: &proto::ClientCheckpoint) -> SealedCheckpoint {
    let bytes = state.encode_to_vec();
    let sha256 = Sha256::digest(&bytes).into();
    SealedCheckpoint {
        generation: state.generation,
        bytes,
        sha256,
    }
}

pub(super) fn decode_checkpoint(
    checkpoint: SealedCheckpoint,
) -> Result<proto::ClientCheckpoint, Error> {
    if Sha256::digest(&checkpoint.bytes).as_slice() != checkpoint.sha256 {
        return Err(Error::Persistence(StorageError::Corrupt));
    }
    let state = proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice())
        .map_err(|_| Error::Persistence(StorageError::Corrupt))?;
    if state.version != PROTOCOL_VERSION || state.generation != checkpoint.generation {
        return Err(Error::Persistence(StorageError::Corrupt));
    }
    Ok(state)
}
