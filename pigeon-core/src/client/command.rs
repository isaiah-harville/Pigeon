use prost::Message;

use crate::Error;
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
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode_to_vec()
    }

    pub fn command_id(&self) -> &str {
        &self.inner.command_id
    }
}
