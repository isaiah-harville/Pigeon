use prost::Message;

use super::GroupId;
use crate::Error;
use crate::wire::{
    GROUP_ID_BYTES, IDENTITY_KEY_BYTES, MAX_GROUP_APPLICATION_BYTES, MAX_MLS_OBJECT_BYTES,
    MAX_POLICY_STRING_BYTES, PROTOCOL_VERSION, proto,
};

pub const GROUP_MESSAGE_ID_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GroupMessageId([u8; GROUP_MESSAGE_ID_BYTES]);

impl GroupMessageId {
    pub fn from_bytes(bytes: [u8; GROUP_MESSAGE_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; GROUP_MESSAGE_ID_BYTES] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupApplication {
    Text {
        body: Vec<u8>,
        reply_to: Option<GroupMessageId>,
        sender_timestamp_ms: i64,
    },
    Reaction {
        target: GroupMessageId,
        reaction: String,
        sender_timestamp_ms: i64,
    },
    Acknowledgement {
        original_sender: [u8; IDENTITY_KEY_BYTES],
        message_id: GroupMessageId,
        sender_timestamp_ms: i64,
    },
}

impl GroupApplication {
    pub fn text(body: Vec<u8>, reply_to: Option<GroupMessageId>, sender_timestamp_ms: i64) -> Self {
        Self::Text {
            body,
            reply_to,
            sender_timestamp_ms,
        }
    }

    pub fn reaction(
        target: GroupMessageId,
        reaction: impl Into<String>,
        sender_timestamp_ms: i64,
    ) -> Self {
        Self::Reaction {
            target,
            reaction: reaction.into(),
            sender_timestamp_ms,
        }
    }

    pub fn acknowledgement(
        original_sender: [u8; IDENTITY_KEY_BYTES],
        message_id: GroupMessageId,
        sender_timestamp_ms: i64,
    ) -> Self {
        Self::Acknowledgement {
            original_sender,
            message_id,
            sender_timestamp_ms,
        }
    }

    pub fn text_body(&self) -> Option<&[u8]> {
        match self {
            Self::Text { body, .. } => Some(body),
            _ => None,
        }
    }

    fn sender_timestamp_ms(&self) -> i64 {
        match self {
            Self::Text {
                sender_timestamp_ms,
                ..
            }
            | Self::Reaction {
                sender_timestamp_ms,
                ..
            }
            | Self::Acknowledgement {
                sender_timestamp_ms,
                ..
            } => *sender_timestamp_ms,
        }
    }

    fn into_proto(self) -> Result<proto::group_application_content::Body, Error> {
        use proto::group_application_content::Body;
        match self {
            Self::Text { body, reply_to, .. } => {
                if body.len() > MAX_GROUP_APPLICATION_BYTES {
                    return Err(Error::ResourceLimit("group text bytes"));
                }
                Ok(Body::Text(proto::GroupText {
                    body,
                    reply_to_message_id: reply_to
                        .map(|id| id.as_bytes().to_vec())
                        .unwrap_or_default(),
                }))
            }
            Self::Reaction {
                target, reaction, ..
            } => {
                if reaction.is_empty() || reaction.len() > MAX_POLICY_STRING_BYTES {
                    return Err(Error::ResourceLimit("group reaction bytes"));
                }
                Ok(Body::Reaction(proto::GroupReaction {
                    target_message_id: target.as_bytes().to_vec(),
                    reaction,
                }))
            }
            Self::Acknowledgement {
                original_sender,
                message_id,
                ..
            } => Ok(Body::Acknowledgement(proto::GroupAcknowledgement {
                original_sender_identity: original_sender.to_vec(),
                message_id: message_id.as_bytes().to_vec(),
            })),
        }
    }

    fn from_proto(
        body: proto::group_application_content::Body,
        sender_timestamp_ms: i64,
    ) -> Result<Self, Error> {
        use proto::group_application_content::Body;
        match body {
            Body::Text(text) => {
                if text.body.len() > MAX_GROUP_APPLICATION_BYTES {
                    return Err(Error::ResourceLimit("group text bytes"));
                }
                let reply_to = optional_message_id(&text.reply_to_message_id)?;
                Ok(Self::Text {
                    body: text.body,
                    reply_to,
                    sender_timestamp_ms,
                })
            }
            Body::Reaction(reaction) => {
                if reaction.reaction.is_empty() || reaction.reaction.len() > MAX_POLICY_STRING_BYTES
                {
                    return Err(Error::ResourceLimit("group reaction bytes"));
                }
                Ok(Self::Reaction {
                    target: message_id(&reaction.target_message_id)?,
                    reaction: reaction.reaction,
                    sender_timestamp_ms,
                })
            }
            Body::Acknowledgement(acknowledgement) => Ok(Self::Acknowledgement {
                original_sender: fixed_bytes(&acknowledgement.original_sender_identity)?,
                message_id: message_id(&acknowledgement.message_id)?,
                sender_timestamp_ms,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupCiphertext {
    group_id: GroupId,
    epoch: u64,
    message_id: GroupMessageId,
    ciphertext: Vec<u8>,
}

impl GroupCiphertext {
    pub(crate) fn new(
        group_id: GroupId,
        epoch: u64,
        message_id: GroupMessageId,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            group_id,
            epoch,
            message_id,
            ciphertext,
        }
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn message_id(&self) -> GroupMessageId {
        self.message_id
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupApplicationCiphertext {
            version: PROTOCOL_VERSION,
            group_id: self.group_id.as_bytes().to_vec(),
            epoch: self.epoch,
            message_id: self.message_id.as_bytes().to_vec(),
            ciphertext: self.ciphertext.clone(),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("group ciphertext bytes"));
        }
        let wire =
            proto::GroupApplicationCiphertext::decode(bytes).map_err(|_| Error::Serialization)?;
        if wire.version != PROTOCOL_VERSION
            || wire.group_id.len() != GROUP_ID_BYTES
            || wire.ciphertext.len() > MAX_MLS_OBJECT_BYTES
        {
            return Err(Error::Serialization);
        }
        Ok(Self {
            group_id: GroupId::from_bytes(fixed_bytes(&wire.group_id)?),
            epoch: wire.epoch,
            message_id: message_id(&wire.message_id)?,
            ciphertext: wire.ciphertext,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedGroupMessage {
    group_id: GroupId,
    epoch: u64,
    sender_identity: [u8; IDENTITY_KEY_BYTES],
    message_id: GroupMessageId,
    application: GroupApplication,
}

impl AuthenticatedGroupMessage {
    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn sender_identity(&self) -> [u8; IDENTITY_KEY_BYTES] {
        self.sender_identity
    }

    pub fn message_id(&self) -> GroupMessageId {
        self.message_id
    }

    pub fn application(&self) -> &GroupApplication {
        &self.application
    }
}

pub(crate) fn encode_content(
    group_id: GroupId,
    epoch: u64,
    sender_identity: [u8; IDENTITY_KEY_BYTES],
    message_id: GroupMessageId,
    application: GroupApplication,
) -> Result<Vec<u8>, Error> {
    let sender_timestamp_ms = application.sender_timestamp_ms();
    let content = proto::GroupApplicationContent {
        version: PROTOCOL_VERSION,
        group_id: group_id.as_bytes().to_vec(),
        epoch,
        sender_identity: sender_identity.to_vec(),
        message_id: message_id.as_bytes().to_vec(),
        sender_timestamp_ms,
        body: Some(application.into_proto()?),
    };
    let bytes = content.encode_to_vec();
    if bytes.len() > MAX_GROUP_APPLICATION_BYTES {
        return Err(Error::ResourceLimit("group application bytes"));
    }
    Ok(bytes)
}

pub(crate) fn decode_content(
    bytes: &[u8],
    outer: &GroupCiphertext,
    authenticated_sender: [u8; IDENTITY_KEY_BYTES],
) -> Result<AuthenticatedGroupMessage, Error> {
    if bytes.len() > MAX_GROUP_APPLICATION_BYTES {
        return Err(Error::ResourceLimit("group application bytes"));
    }
    let content =
        proto::GroupApplicationContent::decode(bytes).map_err(|_| Error::Serialization)?;
    let group_id = GroupId::from_bytes(fixed_bytes(&content.group_id)?);
    let sender_identity = fixed_bytes(&content.sender_identity)?;
    let message_id = message_id(&content.message_id)?;
    if content.version != PROTOCOL_VERSION
        || group_id != outer.group_id
        || content.epoch != outer.epoch
        || message_id != outer.message_id
        || sender_identity != authenticated_sender
    {
        return Err(Error::InvalidSignature);
    }
    let application = GroupApplication::from_proto(
        content.body.ok_or(Error::MalformedBundle)?,
        content.sender_timestamp_ms,
    )?;
    Ok(AuthenticatedGroupMessage {
        group_id,
        epoch: content.epoch,
        sender_identity,
        message_id,
        application,
    })
}

fn message_id(bytes: &[u8]) -> Result<GroupMessageId, Error> {
    Ok(GroupMessageId::from_bytes(fixed_bytes(bytes)?))
}

fn optional_message_id(bytes: &[u8]) -> Result<Option<GroupMessageId>, Error> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        message_id(bytes).map(Some)
    }
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Serialization)
}
