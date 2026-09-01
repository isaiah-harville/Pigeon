//! Versioned protobuf boundary and validation.

mod limits;

use prost::Message;

use crate::Error;

pub use limits::*;

#[allow(dead_code)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/pigeon.wire.v1.rs"));
}

pub fn decode_client_command(bytes: &[u8]) -> Result<proto::ClientCommand, Error> {
    check_bytes(
        bytes.len(),
        MAX_CLIENT_COMMAND_BYTES,
        "client command bytes",
    )?;
    let command = proto::ClientCommand::decode(bytes).map_err(|_| Error::MalformedBundle)?;
    validate_client_command(&command)?;
    Ok(command)
}

pub(crate) fn validate_client_command(command: &proto::ClientCommand) -> Result<(), Error> {
    if command.version != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion {
            kind: "command",
            version: command.version,
        });
    }
    check_bytes(command.command_id.len(), MAX_STABLE_ID_BYTES, "command id")?;
    if command.command_id.is_empty() {
        return Err(Error::MalformedBundle);
    }

    match command.body.as_ref().ok_or(Error::MalformedBundle)? {
        proto::client_command::Body::CreateGroup(create) => {
            check_bytes(create.name.len(), MAX_GROUP_NAME_BYTES, "group name")?;
            check_count(
                create.member_identities.len(),
                MAX_GROUP_MEMBERS - 1,
                "group members",
            )?;
            check_bytes(create.relay_url.len(), MAX_RELAY_URL_BYTES, "relay url")?;
            if create.coordinator_public_key.len() != IDENTITY_KEY_BYTES {
                return Err(Error::InvalidKey);
            }
            for identity in &create.member_identities {
                if identity.len() != IDENTITY_KEY_BYTES {
                    return Err(Error::InvalidKey);
                }
            }
        }
        proto::client_command::Body::SendGroupMessage(send) => {
            check_exact_group_id(&send.group_id)?;
            check_bytes(send.message_id.len(), MAX_STABLE_ID_BYTES, "message id")?;
            check_bytes(
                send.body.len(),
                MAX_GROUP_APPLICATION_BYTES,
                "group application bytes",
            )?;
            check_bytes(
                send.reply_to_message_id.len(),
                MAX_STABLE_ID_BYTES,
                "reply id",
            )?;
        }
        proto::client_command::Body::ApplyInbound(inbound) => {
            check_bytes(
                inbound.payload.len(),
                MAX_MLS_OBJECT_BYTES,
                "inbound object bytes",
            )?;
            check_bytes(
                inbound.request_id.len(),
                MAX_STABLE_ID_BYTES,
                "inbound request id",
            )?;
            let kind =
                proto::OutboundKind::try_from(inbound.kind).map_err(|_| Error::MalformedBundle)?;
            if inbound.request_id.is_empty()
                || !matches!(
                    kind,
                    proto::OutboundKind::GroupJoinRequest
                        | proto::OutboundKind::GroupJoinMaterial
                        | proto::OutboundKind::GroupWelcome
                        | proto::OutboundKind::GroupMessage
                        | proto::OutboundKind::GroupCoordinator
                        | proto::OutboundKind::GroupLeaveProposal
                )
            {
                return Err(Error::MalformedBundle);
            }
        }
        proto::client_command::Body::ChangeGroupPolicy(change) => {
            check_exact_group_id(&change.group_id)?;
            if !change.subject_identity.is_empty()
                && change.subject_identity.len() != IDENTITY_KEY_BYTES
            {
                return Err(Error::InvalidKey);
            }
            check_bytes(
                change.string_value.len(),
                MAX_POLICY_STRING_BYTES,
                "policy string",
            )?;
        }
        proto::client_command::Body::AcknowledgeEffects(acknowledgement) => {
            check_count(
                acknowledgement.outbound_item_ids.len(),
                MAX_PENDING_OUTBOUND_ENTRIES,
                "acknowledged outbound items",
            )?;
            check_count(
                acknowledgement.event_ids.len(),
                MAX_PENDING_OUTBOUND_ENTRIES,
                "acknowledged events",
            )?;
            for id in acknowledgement
                .outbound_item_ids
                .iter()
                .chain(&acknowledgement.event_ids)
            {
                if id.is_empty() {
                    return Err(Error::MalformedBundle);
                }
                check_bytes(id.len(), MAX_STABLE_ID_BYTES, "effect id")?;
            }
        }
        proto::client_command::Body::EnsurePairwiseAccount(_) => {}
    }
    Ok(())
}

fn check_exact_group_id(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() == GROUP_ID_BYTES {
        Ok(())
    } else {
        Err(Error::MalformedBundle)
    }
}

fn check_bytes(actual: usize, maximum: usize, label: &'static str) -> Result<(), Error> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(Error::ResourceLimit(label))
    }
}

fn check_count(actual: usize, maximum: usize, label: &'static str) -> Result<(), Error> {
    check_bytes(actual, maximum, label)
}
