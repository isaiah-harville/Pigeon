use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;

use super::{PigeonGroupPolicy, PolicyEvent, relay_capability_id};
use crate::Error;
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::wire::{MAX_GROUP_MEMBERS, MAX_MLS_OBJECT_BYTES, proto};

const REGISTRATION_VERSION: u32 = 2;
const CONTROL_VERSION: u32 = 2;
const REGISTRATION_DOMAIN: &[u8] = b"pigeon.relay.group.registration.v2";
const CHALLENGE_DOMAIN: &[u8] = b"pigeon.relay.group.challenge.v2";

pub(crate) fn challenge_transcript(
    coordination_id: [u8; 32],
    capability_id: [u8; 32],
    nonce: [u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(CHALLENGE_DOMAIN.len() + 96);
    transcript.extend_from_slice(CHALLENGE_DOMAIN);
    transcript.extend_from_slice(&coordination_id);
    transcript.extend_from_slice(&capability_id);
    transcript.extend_from_slice(&nonce);
    transcript
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRelayCapability {
    capability_id: [u8; 32],
    public_key: [u8; 32],
    can_append: bool,
    can_read: bool,
    can_control: bool,
}

impl GroupRelayCapability {
    pub fn capability_id(&self) -> [u8; 32] {
        self.capability_id
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupRelayControlKind {
    ReplaceAll,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRelayControl {
    coordination_id: [u8; 32],
    kind: GroupRelayControlKind,
    capabilities: Vec<GroupRelayCapability>,
    expected_generation: u64,
    new_generation: u64,
    permanent_controller_public_key: [u8; 32],
}

impl GroupRelayControl {
    pub fn for_transition(
        prior: &PigeonGroupPolicy,
        next: &PigeonGroupPolicy,
        _prior_epoch: u64,
        next_epoch: u64,
        event: &PolicyEvent,
    ) -> Result<Option<Self>, super::PolicyError> {
        prior.relay_capability_delta(next, event)?;
        Ok(Some(Self {
            coordination_id: prior.coordination_id(),
            kind: GroupRelayControlKind::ReplaceAll,
            capabilities: capabilities_for_policy(next, next_epoch)?,
            expected_generation: prior.revision(),
            new_generation: next.revision(),
            permanent_controller_public_key: next
                .member_capability_key(next.owner())
                .ok_or(super::PolicyError::InvalidRoster)?,
        }))
    }

    pub fn coordination_id(&self) -> [u8; 32] {
        self.coordination_id
    }

    pub fn kind(&self) -> GroupRelayControlKind {
        self.kind
    }

    pub fn capabilities(&self) -> &[GroupRelayCapability] {
        &self.capabilities
    }

    pub fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    pub fn new_generation(&self) -> u64 {
        self.new_generation
    }

    pub fn permanent_controller_public_key(&self) -> [u8; 32] {
        self.permanent_controller_public_key
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupRelayControl {
            version: CONTROL_VERSION,
            coordination_id: self.coordination_id.to_vec(),
            kind: proto::GroupRelayControlKind::ReplaceAll as i32,
            public_key: Vec::new(),
            capabilities: self.capabilities.iter().map(capability_proto).collect(),
            expected_generation: self.expected_generation,
            new_generation: self.new_generation,
            permanent_controller_public_key: self.permanent_controller_public_key.to_vec(),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("group relay control bytes"));
        }
        let control = proto::GroupRelayControl::decode(bytes).map_err(|_| Error::Serialization)?;
        if control.version != CONTROL_VERSION
            || proto::GroupRelayControlKind::try_from(control.kind)
                .map_err(|_| Error::Serialization)?
                != proto::GroupRelayControlKind::ReplaceAll
            || control.new_generation != control.expected_generation.saturating_add(1)
        {
            return Err(Error::Serialization);
        }
        let capabilities = control
            .capabilities
            .into_iter()
            .map(capability_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        validate_capabilities(&capabilities)?;
        Ok(Self {
            coordination_id: fixed(&control.coordination_id)?,
            kind: GroupRelayControlKind::ReplaceAll,
            capabilities,
            expected_generation: control.expected_generation,
            new_generation: control.new_generation,
            permanent_controller_public_key: fixed(&control.permanent_controller_public_key)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRelayRegistration {
    coordination_id: [u8; 32],
    capabilities: Vec<GroupRelayCapability>,
    signature: [u8; 64],
    authorization_generation: u64,
    permanent_controller_public_key: [u8; 32],
}

impl GroupRelayRegistration {
    pub fn create(
        identity: &impl SecureIdentity,
        policy: &PigeonGroupPolicy,
        epoch: u64,
    ) -> Result<Self, Error> {
        let signer = identity.ensure_public_key(IdentityPurpose::GroupCapability(
            *policy.group_id().as_bytes(),
        ))?;
        if !policy
            .admins()
            .iter()
            .filter_map(|admin| policy.member_capability_key(*admin))
            .any(|key| key == signer)
        {
            return Err(Error::InvalidSignature);
        }
        let capabilities = capabilities_for_policy(policy, epoch)?;
        let permanent_controller_public_key = policy
            .member_capability_key(policy.owner())
            .ok_or(Error::InvalidKey)?;
        let signature = identity.sign(
            IdentityPurpose::GroupCapability(*policy.group_id().as_bytes()),
            &registration_transcript(
                policy.coordination_id(),
                policy.revision(),
                permanent_controller_public_key,
                &capabilities,
            ),
        )?;
        Ok(Self {
            coordination_id: policy.coordination_id(),
            capabilities,
            signature,
            authorization_generation: policy.revision(),
            permanent_controller_public_key,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        validate_capabilities(&self.capabilities)?;
        if !self.capabilities.iter().any(|capability| {
            capability.public_key == self.permanent_controller_public_key && capability.can_control
        }) {
            return Err(Error::InvalidSignature);
        }
        let transcript = registration_transcript(
            self.coordination_id,
            self.authorization_generation,
            self.permanent_controller_public_key,
            &self.capabilities,
        );
        let valid_signers = self
            .capabilities
            .iter()
            .filter(|capability| capability.can_control)
            .filter(|capability| {
                VerifyingKey::from_bytes(&capability.public_key).is_ok_and(|key| {
                    key.verify_strict(&transcript, &Signature::from_bytes(&self.signature))
                        .is_ok()
                })
            })
            .count();
        (valid_signers == 1)
            .then_some(())
            .ok_or(Error::InvalidSignature)
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

    pub fn authorization_generation(&self) -> u64 {
        self.authorization_generation
    }

    pub fn permanent_controller_public_key(&self) -> [u8; 32] {
        self.permanent_controller_public_key
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupRelayRegistration {
            version: REGISTRATION_VERSION,
            coordination_id: self.coordination_id.to_vec(),
            capabilities: self.capabilities.iter().map(capability_proto).collect(),
            signature: self.signature.to_vec(),
            authorization_generation: self.authorization_generation,
            permanent_controller_public_key: self.permanent_controller_public_key.to_vec(),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("group relay registration bytes"));
        }
        let value =
            proto::GroupRelayRegistration::decode(bytes).map_err(|_| Error::Serialization)?;
        if value.version != REGISTRATION_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group relay registration",
                version: value.version,
            });
        }
        let registration = Self {
            coordination_id: fixed(&value.coordination_id)?,
            capabilities: value
                .capabilities
                .into_iter()
                .map(capability_from_proto)
                .collect::<Result<_, _>>()?,
            signature: value
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidSignature)?,
            authorization_generation: value.authorization_generation,
            permanent_controller_public_key: fixed(&value.permanent_controller_public_key)?,
        };
        registration.verify()?;
        Ok(registration)
    }
}

fn capabilities_for_policy(
    policy: &PigeonGroupPolicy,
    epoch: u64,
) -> Result<Vec<GroupRelayCapability>, super::PolicyError> {
    let roster_hash = policy.roster_hash();
    let mut capabilities = policy
        .members()
        .iter()
        .map(|member| {
            let public_key = policy
                .member_capability_key(*member)
                .ok_or(super::PolicyError::InvalidRoster)?;
            Ok(GroupRelayCapability {
                capability_id: relay_capability_id(
                    *policy.group_id().as_bytes(),
                    policy.coordination_id(),
                    epoch,
                    policy.revision(),
                    roster_hash,
                    public_key,
                ),
                public_key,
                can_append: true,
                can_read: true,
                can_control: policy.is_admin(*member),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    capabilities.sort_unstable_by_key(|capability| capability.capability_id);
    Ok(capabilities)
}

fn validate_capabilities(capabilities: &[GroupRelayCapability]) -> Result<(), Error> {
    if capabilities.len() < 3
        || capabilities.len() > MAX_GROUP_MEMBERS
        || capabilities
            .windows(2)
            .any(|pair| pair[0].capability_id >= pair[1].capability_id)
        || !capabilities.iter().any(|capability| capability.can_control)
        || capabilities.iter().any(|capability| {
            !capability.can_append
                || !capability.can_read
                || capability.capability_id == [0; 32]
                || VerifyingKey::from_bytes(&capability.public_key).is_err()
        })
    {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

fn capability_proto(capability: &GroupRelayCapability) -> proto::GroupRelayCapability {
    proto::GroupRelayCapability {
        public_key: capability.public_key.to_vec(),
        can_append: capability.can_append,
        can_read: capability.can_read,
        can_control: capability.can_control,
        capability_id: capability.capability_id.to_vec(),
    }
}

fn capability_from_proto(
    value: proto::GroupRelayCapability,
) -> Result<GroupRelayCapability, Error> {
    Ok(GroupRelayCapability {
        capability_id: fixed(&value.capability_id)?,
        public_key: fixed(&value.public_key)?,
        can_append: value.can_append,
        can_read: value.can_read,
        can_control: value.can_control,
    })
}

fn registration_transcript(
    coordination_id: [u8; 32],
    generation: u64,
    permanent_controller_public_key: [u8; 32],
    capabilities: &[GroupRelayCapability],
) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(REGISTRATION_DOMAIN.len() + 76 + capabilities.len() * 67);
    transcript.extend_from_slice(REGISTRATION_DOMAIN);
    transcript.extend_from_slice(&coordination_id);
    transcript.extend_from_slice(&generation.to_be_bytes());
    transcript.extend_from_slice(&permanent_controller_public_key);
    transcript.extend_from_slice(&(capabilities.len() as u32).to_be_bytes());
    for capability in capabilities {
        transcript.extend_from_slice(&capability.capability_id);
        transcript.extend_from_slice(&capability.public_key);
        transcript.push(capability.can_append.into());
        transcript.push(capability.can_read.into());
        transcript.push(capability.can_control.into());
    }
    transcript
}

fn fixed(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::InvalidKey)
}
