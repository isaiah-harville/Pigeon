use prost::Message;

use crate::Error;
use crate::group::GroupId;
use crate::wire::{self, PROTOCOL_VERSION, proto};

#[derive(Clone, Debug)]
pub struct ClientCommand {
    pub(crate) inner: proto::ClientCommand,
}

impl ClientCommand {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            inner: wire::decode_client_command(bytes)?,
        })
    }

    pub fn create_group(
        command_id: impl Into<String>,
        name: impl Into<String>,
        member_identities: Vec<[u8; 32]>,
        relay_url: impl Into<String>,
        coordinator_public_key: [u8; 32],
        mesh_enabled: bool,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::CreateGroup(
                proto::CreateGroup {
                    name: name.into(),
                    member_identities: member_identities
                        .into_iter()
                        .map(|identity| identity.to_vec())
                        .collect(),
                    relay_url: relay_url.into(),
                    mesh_enabled,
                    coordinator_public_key: coordinator_public_key.to_vec(),
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode_to_vec()
    }

    pub fn apply_group_join_request(
        command_id: impl Into<String>,
        request_id: impl Into<String>,
        request: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_inbound(
            command_id,
            request_id,
            proto::OutboundKind::GroupJoinRequest,
            request,
        )
    }

    pub fn apply_group_join_material(
        command_id: impl Into<String>,
        request_id: impl Into<String>,
        material: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_inbound(
            command_id,
            request_id,
            proto::OutboundKind::GroupJoinMaterial,
            material,
        )
    }

    fn apply_inbound(
        command_id: impl Into<String>,
        request_id: impl Into<String>,
        kind: proto::OutboundKind,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::ApplyInbound(
                proto::ApplyInbound {
                    kind: kind as i32,
                    payload,
                    request_id: request_id.into(),
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn send_group_text(
        command_id: impl Into<String>,
        group_id: GroupId,
        body: Vec<u8>,
        reply_to_message_id: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::send_group_text_at(command_id, group_id, body, reply_to_message_id, 0)
    }

    pub fn send_group_text_at(
        command_id: impl Into<String>,
        group_id: GroupId,
        body: Vec<u8>,
        reply_to_message_id: impl Into<String>,
        sender_timestamp_ms: i64,
    ) -> Result<Self, Error> {
        let command_id = command_id.into();
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.clone(),
            body: Some(proto::client_command::Body::SendGroupMessage(
                proto::SendGroupMessage {
                    group_id: group_id.as_bytes().to_vec(),
                    message_id: command_id,
                    body,
                    reply_to_message_id: reply_to_message_id.into(),
                    sender_timestamp_ms,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn apply_group_welcome(
        command_id: impl Into<String>,
        welcome: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_group_input(command_id, proto::OutboundKind::GroupWelcome, welcome)
    }

    pub fn apply_group_message(
        command_id: impl Into<String>,
        ciphertext: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_group_input(command_id, proto::OutboundKind::GroupMessage, ciphertext)
    }

    fn apply_group_input(
        command_id: impl Into<String>,
        kind: proto::OutboundKind,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        let command_id = command_id.into();
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.clone(),
            body: Some(proto::client_command::Body::ApplyInbound(
                proto::ApplyInbound {
                    kind: kind as i32,
                    payload,
                    request_id: command_id,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn command_id(&self) -> &str {
        &self.inner.command_id
    }
}
