use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;

use super::super::{IdentityPurpose, SecureIdentity};
use crate::Error;
use crate::group::GroupId;
use crate::wire::{MAX_MLS_OBJECT_BYTES, proto};

const JOIN_REQUEST_VERSION: u32 = 2;
const JOIN_REQUEST_DOMAIN: &[u8] = b"pigeon.identity.group-join-request.v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupJoinRequest {
    group_id: GroupId,
    coordination_id: [u8; 32],
    requester_identity: [u8; 32],
    owner_identity: [u8; 32],
    relay_url: String,
    signature: [u8; 64],
}

impl GroupJoinRequest {
    pub fn create(
        identity: &impl SecureIdentity,
        group_id: GroupId,
        coordination_id: [u8; 32],
        relay_url: impl Into<String>,
    ) -> Result<Self, Error> {
        let owner_identity = identity.ensure_public_key(IdentityPurpose::Root)?;
        Self::create_for_owner(
            identity,
            owner_identity,
            group_id,
            coordination_id,
            relay_url,
        )
    }

    pub fn create_for_owner(
        identity: &impl SecureIdentity,
        owner_identity: [u8; 32],
        group_id: GroupId,
        coordination_id: [u8; 32],
        relay_url: impl Into<String>,
    ) -> Result<Self, Error> {
        let requester_identity = identity.ensure_public_key(IdentityPurpose::Root)?;
        let relay_url = relay_url.into();
        validate_relay_url(&relay_url)?;
        let signature = identity.sign(
            IdentityPurpose::Root,
            &join_request_transcript(
                group_id,
                coordination_id,
                requester_identity,
                owner_identity,
                &relay_url,
            ),
        )?;
        Ok(Self {
            group_id,
            coordination_id,
            requester_identity,
            owner_identity,
            relay_url,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        validate_relay_url(&self.relay_url)?;
        VerifyingKey::from_bytes(&self.owner_identity).map_err(|_| Error::InvalidKey)?;
        let requester =
            VerifyingKey::from_bytes(&self.requester_identity).map_err(|_| Error::InvalidKey)?;
        requester
            .verify_strict(
                &join_request_transcript(
                    self.group_id,
                    self.coordination_id,
                    self.requester_identity,
                    self.owner_identity,
                    &self.relay_url,
                ),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::InvalidSignature)
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn coordination_id(&self) -> [u8; 32] {
        self.coordination_id
    }

    pub fn requester_identity(&self) -> [u8; 32] {
        self.requester_identity
    }

    pub fn owner_identity(&self) -> [u8; 32] {
        self.owner_identity
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupJoinRequest {
            version: JOIN_REQUEST_VERSION,
            group_id: self.group_id.as_bytes().to_vec(),
            coordination_id: self.coordination_id.to_vec(),
            requester_identity: self.requester_identity.to_vec(),
            owner_identity: self.owner_identity.to_vec(),
            relay_url: self.relay_url.clone(),
            signature: self.signature.to_vec(),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("group join request bytes"));
        }
        let request = proto::GroupJoinRequest::decode(bytes).map_err(|_| Error::Serialization)?;
        if request.version != JOIN_REQUEST_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group join request",
                version: request.version,
            });
        }
        let request = Self {
            group_id: GroupId::from_bytes(to_array(&request.group_id)?),
            coordination_id: to_array(&request.coordination_id)?,
            requester_identity: to_array(&request.requester_identity)?,
            owner_identity: to_array(&request.owner_identity)?,
            relay_url: request.relay_url,
            signature: request
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidSignature)?,
        };
        request.verify()?;
        Ok(request)
    }
}

fn join_request_transcript(
    group_id: GroupId,
    coordination_id: [u8; 32],
    requester_identity: [u8; 32],
    owner_identity: [u8; 32],
    relay_url: &str,
) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(JOIN_REQUEST_DOMAIN.len() + 8 + 32 * 4 + relay_url.len());
    transcript.extend_from_slice(JOIN_REQUEST_DOMAIN);
    transcript.extend_from_slice(&JOIN_REQUEST_VERSION.to_be_bytes());
    transcript.extend_from_slice(group_id.as_bytes());
    transcript.extend_from_slice(&coordination_id);
    transcript.extend_from_slice(&requester_identity);
    transcript.extend_from_slice(&owner_identity);
    transcript.extend_from_slice(&(relay_url.len() as u32).to_be_bytes());
    transcript.extend_from_slice(relay_url.as_bytes());
    transcript
}

fn validate_relay_url(relay_url: &str) -> Result<(), Error> {
    if relay_url.is_empty()
        || relay_url.len() > crate::wire::MAX_RELAY_URL_BYTES
        || !(relay_url.starts_with("https://") || relay_url.starts_with("wss://"))
    {
        return Err(Error::MalformedBundle);
    }
    Ok(())
}

fn to_array(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::InvalidKey)
}
