use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;

use super::super::{IdentityPurpose, ReservedKeyPackage, SecureIdentity};
use crate::Error;
use crate::group::GroupId;
use crate::storage::TransactionalOpenMlsStorage;
use crate::wire::{MAX_MLS_OBJECT_BYTES, proto};

const MEMBER_KEYS_VERSION: u32 = 1;
const JOIN_MATERIAL_VERSION: u32 = 1;
const MEMBER_KEYS_DOMAIN: &[u8] = b"pigeon.identity.group-member-keys.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMemberKeys {
    group_id: GroupId,
    coordination_id: [u8; 32],
    intended_creator: [u8; 32],
    member_identity: [u8; 32],
    capability_public_key: [u8; 32],
    recovery_public_key: [u8; 32],
    binding_signature: [u8; 64],
}

impl GroupMemberKeys {
    pub fn issue(
        identity: &impl SecureIdentity,
        intended_creator: [u8; 32],
        group_id: GroupId,
        coordination_id: [u8; 32],
    ) -> Result<Self, Error> {
        let member_identity = identity.ensure_public_key(IdentityPurpose::Root)?;
        let capability_public_key =
            identity.ensure_public_key(IdentityPurpose::GroupCapability(*group_id.as_bytes()))?;
        let recovery_public_key =
            identity.ensure_public_key(IdentityPurpose::GroupRecovery(*group_id.as_bytes()))?;
        let binding_signature = identity.sign(
            IdentityPurpose::Root,
            &member_keys_transcript(
                group_id,
                coordination_id,
                intended_creator,
                member_identity,
                capability_public_key,
                recovery_public_key,
            ),
        )?;
        Ok(Self {
            group_id,
            coordination_id,
            intended_creator,
            member_identity,
            capability_public_key,
            recovery_public_key,
            binding_signature,
        })
    }

    pub fn verify(
        &self,
        intended_creator: [u8; 32],
        group_id: GroupId,
        coordination_id: [u8; 32],
    ) -> Result<(), Error> {
        if self.intended_creator != intended_creator
            || self.group_id != group_id
            || self.coordination_id != coordination_id
            || self.capability_public_key == [0; 32]
            || self.recovery_public_key == [0; 32]
        {
            return Err(Error::InvalidSignature);
        }
        VerifyingKey::from_bytes(&self.capability_public_key).map_err(|_| Error::InvalidKey)?;
        VerifyingKey::from_bytes(&self.recovery_public_key).map_err(|_| Error::InvalidKey)?;
        let root =
            VerifyingKey::from_bytes(&self.member_identity).map_err(|_| Error::InvalidKey)?;
        root.verify_strict(
            &member_keys_transcript(
                self.group_id,
                self.coordination_id,
                self.intended_creator,
                self.member_identity,
                self.capability_public_key,
                self.recovery_public_key,
            ),
            &Signature::from_bytes(&self.binding_signature),
        )
        .map_err(|_| Error::InvalidSignature)
    }

    pub fn member_identity(&self) -> [u8; 32] {
        self.member_identity
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn coordination_id(&self) -> [u8; 32] {
        self.coordination_id
    }

    pub fn intended_creator(&self) -> [u8; 32] {
        self.intended_creator
    }

    pub fn capability_public_key(&self) -> [u8; 32] {
        self.capability_public_key
    }

    pub fn recovery_public_key(&self) -> [u8; 32] {
        self.recovery_public_key
    }

    pub(crate) fn to_proto(&self) -> proto::GroupMemberKeys {
        proto::GroupMemberKeys {
            version: MEMBER_KEYS_VERSION,
            group_id: self.group_id.as_bytes().to_vec(),
            coordination_id: self.coordination_id.to_vec(),
            intended_creator: self.intended_creator.to_vec(),
            member_identity: self.member_identity.to_vec(),
            capability_public_key: self.capability_public_key.to_vec(),
            recovery_public_key: self.recovery_public_key.to_vec(),
            binding_signature: self.binding_signature.to_vec(),
        }
    }

    pub(crate) fn from_proto(keys: proto::GroupMemberKeys) -> Result<Self, Error> {
        if keys.version != MEMBER_KEYS_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group member keys",
                version: keys.version,
            });
        }
        Ok(Self {
            group_id: GroupId::from_bytes(to_array(&keys.group_id)?),
            coordination_id: to_array(&keys.coordination_id)?,
            intended_creator: to_array(&keys.intended_creator)?,
            member_identity: to_array(&keys.member_identity)?,
            capability_public_key: to_array(&keys.capability_public_key)?,
            recovery_public_key: to_array(&keys.recovery_public_key)?,
            binding_signature: keys
                .binding_signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidSignature)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct GroupJoinMaterial {
    group_id: GroupId,
    coordination_id: [u8; 32],
    key_package: ReservedKeyPackage,
    member_keys: GroupMemberKeys,
}

impl GroupJoinMaterial {
    pub fn issue(
        identity: &impl SecureIdentity,
        intended_creator: [u8; 32],
        group_id: GroupId,
        coordination_id: [u8; 32],
        storage: &mut TransactionalOpenMlsStorage,
    ) -> Result<Self, Error> {
        Ok(Self {
            group_id,
            coordination_id,
            key_package: ReservedKeyPackage::issue(identity, intended_creator, storage)?,
            member_keys: GroupMemberKeys::issue(
                identity,
                intended_creator,
                group_id,
                coordination_id,
            )?,
        })
    }

    pub fn verify_for(
        &self,
        intended_creator: [u8; 32],
        group_id: GroupId,
        coordination_id: [u8; 32],
    ) -> Result<(), Error> {
        if self.group_id != group_id || self.coordination_id != coordination_id {
            return Err(Error::InvalidSignature);
        }
        self.key_package.verify_for(intended_creator)?;
        self.member_keys
            .verify(intended_creator, group_id, coordination_id)?;
        if self.key_package.issuer() != self.member_keys.member_identity {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    pub fn member_identity(&self) -> [u8; 32] {
        self.member_keys.member_identity()
    }

    pub fn capability_public_key(&self) -> [u8; 32] {
        self.member_keys.capability_public_key()
    }

    pub fn recovery_public_key(&self) -> [u8; 32] {
        self.member_keys.recovery_public_key()
    }

    pub(crate) fn package_hash(&self) -> [u8; 32] {
        self.key_package.package_hash()
    }

    pub(crate) fn key_package(&self) -> ReservedKeyPackage {
        self.key_package.clone()
    }

    /// Returns the signed public-key binding carried with this join material.
    pub fn member_keys(&self) -> GroupMemberKeys {
        self.member_keys.clone()
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupJoinMaterial {
            version: JOIN_MATERIAL_VERSION,
            group_id: self.group_id.as_bytes().to_vec(),
            coordination_id: self.coordination_id.to_vec(),
            reserved_key_package: self.key_package.encode(),
            member_keys: Some(self.member_keys.to_proto()),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("group join material bytes"));
        }
        let material = proto::GroupJoinMaterial::decode(bytes).map_err(|_| Error::Serialization)?;
        if material.version != JOIN_MATERIAL_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group join material",
                version: material.version,
            });
        }
        Ok(Self {
            group_id: GroupId::from_bytes(to_array(&material.group_id)?),
            coordination_id: to_array(&material.coordination_id)?,
            key_package: ReservedKeyPackage::decode(&material.reserved_key_package)?,
            member_keys: GroupMemberKeys::from_proto(
                material.member_keys.ok_or(Error::Serialization)?,
            )?,
        })
    }
}

fn member_keys_transcript(
    group_id: GroupId,
    coordination_id: [u8; 32],
    intended_creator: [u8; 32],
    member_identity: [u8; 32],
    capability_public_key: [u8; 32],
    recovery_public_key: [u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(MEMBER_KEYS_DOMAIN.len() + 4 + 32 * 6);
    transcript.extend_from_slice(MEMBER_KEYS_DOMAIN);
    transcript.extend_from_slice(&MEMBER_KEYS_VERSION.to_be_bytes());
    transcript.extend_from_slice(group_id.as_bytes());
    transcript.extend_from_slice(&coordination_id);
    transcript.extend_from_slice(&intended_creator);
    transcript.extend_from_slice(&member_identity);
    transcript.extend_from_slice(&capability_public_key);
    transcript.extend_from_slice(&recovery_public_key);
    transcript
}

fn to_array(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::InvalidKey)
}
