use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;

use super::GroupId;
use crate::Error;
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::wire::{MAX_GROUP_MEMBERS, MAX_MLS_OBJECT_BYTES, proto};

const REGISTRATION_VERSION: u32 = 1;
const REGISTRATION_DOMAIN: &[u8] = b"pigeon.relay.group.registration.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRelayCapability {
    public_key: [u8; 32],
    can_append: bool,
    can_read: bool,
    can_control: bool,
}

impl GroupRelayCapability {
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub fn can_append(&self) -> bool {
        self.can_append
    }

    pub fn can_read(&self) -> bool {
        self.can_read
    }

    pub fn can_control(&self) -> bool {
        self.can_control
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRelayRegistration {
    coordination_id: [u8; 32],
    capabilities: Vec<GroupRelayCapability>,
    signature: [u8; 64],
}

impl GroupRelayRegistration {
    pub fn create(
        identity: &impl SecureIdentity,
        group_id: GroupId,
        coordination_id: [u8; 32],
        member_capability_keys: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<Self, Error> {
        let controller =
            identity.ensure_public_key(IdentityPurpose::GroupCapability(*group_id.as_bytes()))?;
        let mut capabilities = member_capability_keys
            .into_iter()
            .map(|public_key| GroupRelayCapability {
                public_key,
                can_append: true,
                can_read: true,
                can_control: false,
            })
            .collect::<Vec<_>>();
        capabilities.push(GroupRelayCapability {
            public_key: controller,
            can_append: true,
            can_read: true,
            can_control: true,
        });
        capabilities.sort_unstable_by_key(|capability| capability.public_key);
        validate_capabilities(&capabilities)?;
        let signature = identity.sign(
            IdentityPurpose::GroupCapability(*group_id.as_bytes()),
            &registration_transcript(coordination_id, &capabilities),
        )?;
        Ok(Self {
            coordination_id,
            capabilities,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        validate_capabilities(&self.capabilities)?;
        let controller = self
            .capabilities
            .iter()
            .find(|capability| capability.can_control)
            .ok_or(Error::InvalidSignature)?;
        VerifyingKey::from_bytes(&controller.public_key)
            .map_err(|_| Error::InvalidKey)?
            .verify_strict(
                &registration_transcript(self.coordination_id, &self.capabilities),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::InvalidSignature)
    }

    pub fn coordination_id(&self) -> [u8; 32] {
        self.coordination_id
    }

    pub fn capabilities(&self) -> &[GroupRelayCapability] {
        &self.capabilities
    }

    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupRelayRegistration {
            version: REGISTRATION_VERSION,
            coordination_id: self.coordination_id.to_vec(),
            capabilities: self
                .capabilities
                .iter()
                .map(|capability| proto::GroupRelayCapability {
                    public_key: capability.public_key.to_vec(),
                    can_append: capability.can_append,
                    can_read: capability.can_read,
                    can_control: capability.can_control,
                })
                .collect(),
            signature: self.signature.to_vec(),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("group relay registration bytes"));
        }
        let registration =
            proto::GroupRelayRegistration::decode(bytes).map_err(|_| Error::Serialization)?;
        if registration.version != REGISTRATION_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group relay registration",
                version: registration.version,
            });
        }
        let registration = Self {
            coordination_id: registration
                .coordination_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
            capabilities: registration
                .capabilities
                .into_iter()
                .map(|capability| {
                    Ok(GroupRelayCapability {
                        public_key: capability
                            .public_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::InvalidKey)?,
                        can_append: capability.can_append,
                        can_read: capability.can_read,
                        can_control: capability.can_control,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?,
            signature: registration
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidSignature)?,
        };
        registration.verify()?;
        Ok(registration)
    }
}

fn validate_capabilities(capabilities: &[GroupRelayCapability]) -> Result<(), Error> {
    if capabilities.len() < 3
        || capabilities.len() > MAX_GROUP_MEMBERS
        || capabilities
            .windows(2)
            .any(|pair| pair[0].public_key >= pair[1].public_key)
        || capabilities
            .iter()
            .filter(|capability| capability.can_control)
            .count()
            != 1
        || capabilities.iter().any(|capability| {
            !capability.can_append
                || !capability.can_read
                || VerifyingKey::from_bytes(&capability.public_key).is_err()
        })
    {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

fn registration_transcript(
    coordination_id: [u8; 32],
    capabilities: &[GroupRelayCapability],
) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(REGISTRATION_DOMAIN.len() + 32 + 4 + capabilities.len() * 35);
    transcript.extend_from_slice(REGISTRATION_DOMAIN);
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
