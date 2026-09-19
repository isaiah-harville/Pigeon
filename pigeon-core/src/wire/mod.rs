//! Versioned protobuf boundary and validation.

mod limits;

use prost::Message;

use crate::Error;

pub use limits::*;

pub(crate) const CONTACT_CARD_VERSION: u32 = 3;

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
                    proto::OutboundKind::Pairwise
                        | proto::OutboundKind::GroupJoinRequest
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
        proto::client_command::Body::ConfirmGroupRelayAuthorization(confirmation) => {
            check_exact_group_id(&confirmation.group_id)?;
            if confirmation.capability_id.len() != IDENTITY_KEY_BYTES {
                return Err(Error::InvalidKey);
            }
        }
        proto::client_command::Body::EnsurePairwiseAccount(_) => {}
        proto::client_command::Body::MigrateLegacyPairwiseState(migration) => {
            if migration.format_version != LEGACY_PAIRWISE_MIGRATION_VERSION {
                return Err(Error::UnsupportedVersion {
                    kind: "legacy pairwise migration",
                    version: migration.format_version,
                });
            }
            check_bytes(
                migration.account_state.len(),
                MAX_MLS_OBJECT_BYTES,
                "legacy pairwise account state",
            )?;
            if migration.account_state.is_empty() || migration.fallback_key.len() != 32 {
                return Err(Error::MalformedBundle);
            }
            check_count(
                migration.sessions.len(),
                MAX_PENDING_OUTBOUND_ENTRIES,
                "legacy pairwise sessions",
            )?;
            for session in &migration.sessions {
                if session.remote_identity.len() != IDENTITY_KEY_BYTES || session.state.is_empty() {
                    return Err(Error::MalformedBundle);
                }
                check_bytes(
                    session.state.len(),
                    MAX_MLS_OBJECT_BYTES,
                    "legacy pairwise session state",
                )?;
            }
        }
        proto::client_command::Body::SendDirectApplication(send) => {
            if send.recipient_identity.len() != IDENTITY_KEY_BYTES {
                return Err(Error::InvalidKey);
            }
            validate_direct_application(send.application.as_ref().ok_or(Error::MalformedBundle)?)?;
            check_bytes(
                send.sender_contact_card.len(),
                MAX_CONTACT_CARD_BYTES,
                "sender contact card",
            )?;
            if !send.sender_contact_card.is_empty()
                && !matches!(
                    send.application
                        .as_ref()
                        .and_then(|application| application.body.as_ref()),
                    Some(proto::direct_application::Body::Message(_))
                )
            {
                return Err(Error::MalformedBundle);
            }
        }
        proto::client_command::Body::RegisterPairwiseContact(register) => {
            check_bytes(
                register.prekey_bundle.len(),
                MAX_MLS_OBJECT_BYTES,
                "pairwise prekey bundle",
            )?;
            check_bytes(register.relay_url.len(), MAX_RELAY_URL_BYTES, "relay url")?;
            if register.prekey_bundle.is_empty() {
                return Err(Error::MalformedBundle);
            }
            match proto::PairwiseRelationship::try_from(register.relationship)
                .map_err(|_| Error::MalformedBundle)?
            {
                proto::PairwiseRelationship::Contact
                | proto::PairwiseRelationship::OutgoingRequest => {}
                proto::PairwiseRelationship::Unspecified
                | proto::PairwiseRelationship::IncomingRequest => {
                    return Err(Error::MalformedBundle);
                }
            }
        }
        proto::client_command::Body::SetPairwiseRelationship(set) => {
            if set.identity.len() != IDENTITY_KEY_BYTES {
                return Err(Error::InvalidKey);
            }
            match proto::PairwiseRelationship::try_from(set.relationship)
                .map_err(|_| Error::MalformedBundle)?
            {
                proto::PairwiseRelationship::Contact
                | proto::PairwiseRelationship::OutgoingRequest => {}
                proto::PairwiseRelationship::Unspecified
                | proto::PairwiseRelationship::IncomingRequest => {
                    return Err(Error::MalformedBundle);
                }
            }
        }
        proto::client_command::Body::RemovePairwiseContact(remove) => {
            if remove.identity.len() != IDENTITY_KEY_BYTES {
                return Err(Error::InvalidKey);
            }
        }
        proto::client_command::Body::SendPairwiseControl(send) => {
            if send.recipient_identity.len() != IDENTITY_KEY_BYTES {
                return Err(Error::InvalidKey);
            }
            let kind = proto::OutboundKind::try_from(send.content_kind)
                .map_err(|_| Error::MalformedBundle)?;
            if !matches!(
                kind,
                proto::OutboundKind::GroupJoinRequest
                    | proto::OutboundKind::GroupJoinMaterial
                    | proto::OutboundKind::GroupWelcome
            ) {
                return Err(Error::MalformedBundle);
            }
            check_bytes(
                send.payload.len(),
                MAX_MLS_OBJECT_BYTES,
                "pairwise control payload",
            )?;
            if send.payload.is_empty() {
                return Err(Error::MalformedBundle);
            }
        }
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

pub(crate) fn validate_direct_application(
    application: &proto::DirectApplication,
) -> Result<(), Error> {
    if application.application_id.is_empty() {
        return Err(Error::MalformedBundle);
    }
    check_bytes(
        application.application_id.len(),
        MAX_STABLE_ID_BYTES,
        "direct application id",
    )?;
    match application.body.as_ref().ok_or(Error::MalformedBundle)? {
        proto::direct_application::Body::Message(message) => {
            if message.text.is_empty() || message.sender_timestamp_ms < 0 {
                return Err(Error::MalformedBundle);
            }
            check_bytes(
                message.reply_snippet.len(),
                MAX_STABLE_ID_BYTES,
                "direct reply snippet",
            )?;
            check_bytes(
                message.text.len(),
                MAX_DIRECT_MESSAGE_BYTES,
                "direct message text",
            )
        }
        proto::direct_application::Body::Acknowledgement(acknowledgement) => {
            validate_referenced_message_id(&acknowledgement.message_id)
        }
        proto::direct_application::Body::Reaction(reaction) => {
            validate_referenced_message_id(&reaction.message_id)?;
            if let Some(emoji) = &reaction.emoji {
                if emoji.is_empty() {
                    return Err(Error::MalformedBundle);
                }
                check_bytes(emoji.len(), MAX_DIRECT_REACTION_BYTES, "direct reaction")?;
            }
            Ok(())
        }
        proto::direct_application::Body::EphemeralState(_) => Ok(()),
        proto::direct_application::Body::TransportState(state) => {
            match proto::DirectTransportMode::try_from(state.mode)
                .map_err(|_| Error::MalformedBundle)?
            {
                proto::DirectTransportMode::Relay | proto::DirectTransportMode::Local => Ok(()),
                proto::DirectTransportMode::Unspecified => Err(Error::MalformedBundle),
            }
        }
        proto::direct_application::Body::ScreenshotNotice(_)
        | proto::direct_application::Body::ContactAcceptance(_) => Ok(()),
        proto::direct_application::Body::RelayRecommendation(recommendation) => {
            if recommendation.relay_urls.is_empty() {
                return Err(Error::MalformedBundle);
            }
            check_count(
                recommendation.relay_urls.len(),
                MAX_DIRECT_RELAY_URLS,
                "direct relay urls",
            )?;
            for relay_url in &recommendation.relay_urls {
                check_bytes(relay_url.len(), MAX_RELAY_URL_BYTES, "relay url")?;
                if !(relay_url.starts_with("https://") || relay_url.starts_with("wss://")) {
                    return Err(Error::MalformedBundle);
                }
            }
            Ok(())
        }
    }
}

fn validate_referenced_message_id(message_id: &str) -> Result<(), Error> {
    if message_id.is_empty() {
        return Err(Error::MalformedBundle);
    }
    check_bytes(message_id.len(), MAX_STABLE_ID_BYTES, "direct message id")
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
