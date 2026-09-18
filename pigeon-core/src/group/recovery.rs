use std::collections::BTreeSet;
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

use super::{CoordinatorBinding, PigeonGroupPolicy};
use crate::Error;
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::wire::{MAX_GROUP_MEMBERS, MAX_MLS_OBJECT_BYTES, proto};

const RECOVERY_VERSION: u32 = 1;
const RECOVERY_DOMAIN: &[u8] = b"pigeon.group.recovery.v1";
const CAPABILITY_DOMAIN: &[u8] = b"pigeon.relay.group.capability.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    Malformed,
    InvalidContext,
    InvalidSignature,
    InsufficientQuorum,
    UnauthorizedSigner,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "group recovery validation failed: {self:?}")
    }
}

impl std::error::Error for RecoveryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryProposal {
    group_id: [u8; 32],
    base_epoch: u64,
    base_policy_revision: u64,
    policy_hash: [u8; 32],
    roster_hash: [u8; 32],
    receipt_head: [u8; 32],
    replacement_relay_url: String,
    replacement_coordination_id: [u8; 32],
    replacement_coordinator_public_key: [u8; 32],
    capability_set_hash: [u8; 32],
}

impl RecoveryProposal {
    pub fn new(
        policy: &PigeonGroupPolicy,
        base_epoch: u64,
        receipt_head: [u8; 32],
        replacement_relay_url: impl Into<String>,
        replacement: CoordinatorBinding,
    ) -> Result<Self, RecoveryError> {
        let replacement_relay_url = replacement_relay_url.into();
        if replacement.coordination_id == policy.coordination_id()
            || replacement.public_key == [0; 32]
            || VerifyingKey::from_bytes(&replacement.public_key).is_err()
            || !valid_relay(&replacement_relay_url)
        {
            return Err(RecoveryError::Malformed);
        }
        let next_revision = policy
            .revision()
            .checked_add(1)
            .ok_or(RecoveryError::InvalidContext)?;
        let next_epoch = base_epoch
            .checked_add(1)
            .ok_or(RecoveryError::InvalidContext)?;
        let roster_hash = policy.roster_hash();
        let capability_set_hash = capability_set_hash(
            policy,
            replacement.coordination_id,
            next_epoch,
            next_revision,
            roster_hash,
        )?;
        Ok(Self {
            group_id: *policy.group_id().as_bytes(),
            base_epoch,
            base_policy_revision: policy.revision(),
            policy_hash: policy.policy_hash(),
            roster_hash,
            receipt_head,
            replacement_relay_url,
            replacement_coordination_id: replacement.coordination_id,
            replacement_coordinator_public_key: replacement.public_key,
            capability_set_hash,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryError> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(RecoveryError::Malformed);
        }
        let decoded =
            proto::GroupRecoveryProposal::decode(bytes).map_err(|_| RecoveryError::Malformed)?;
        Self::from_proto(decoded)
    }

    pub fn base_epoch(&self) -> u64 {
        self.base_epoch
    }

    pub fn replacement_relay_url(&self) -> &str {
        &self.replacement_relay_url
    }

    pub fn replacement(&self) -> CoordinatorBinding {
        CoordinatorBinding::new(
            self.replacement_coordination_id,
            self.replacement_coordinator_public_key,
        )
    }

    pub fn capability_set_hash(&self) -> [u8; 32] {
        self.capability_set_hash
    }

    fn verify_context(
        &self,
        policy: &PigeonGroupPolicy,
        epoch: u64,
        receipt_head: [u8; 32],
    ) -> Result<(), RecoveryError> {
        let expected = Self::new(
            policy,
            epoch,
            receipt_head,
            self.replacement_relay_url.clone(),
            self.replacement(),
        )?;
        (self == &expected)
            .then_some(())
            .ok_or(RecoveryError::InvalidContext)
    }

    fn signing_transcript(&self) -> Vec<u8> {
        let encoded = self.encode();
        let mut transcript = Vec::with_capacity(RECOVERY_DOMAIN.len() + 4 + encoded.len());
        transcript.extend_from_slice(RECOVERY_DOMAIN);
        transcript.extend_from_slice(&RECOVERY_VERSION.to_be_bytes());
        transcript.extend_from_slice(&encoded);
        transcript
    }

    fn to_proto(&self) -> proto::GroupRecoveryProposal {
        proto::GroupRecoveryProposal {
            version: RECOVERY_VERSION,
            group_id: self.group_id.to_vec(),
            base_epoch: self.base_epoch,
            base_policy_revision: self.base_policy_revision,
            policy_hash: self.policy_hash.to_vec(),
            roster_hash: self.roster_hash.to_vec(),
            receipt_head: self.receipt_head.to_vec(),
            replacement_relay_url: self.replacement_relay_url.clone(),
            replacement_coordination_id: self.replacement_coordination_id.to_vec(),
            replacement_coordinator_public_key: self.replacement_coordinator_public_key.to_vec(),
            capability_set_hash: self.capability_set_hash.to_vec(),
        }
    }

    fn from_proto(decoded: proto::GroupRecoveryProposal) -> Result<Self, RecoveryError> {
        if decoded.version != RECOVERY_VERSION || !valid_relay(&decoded.replacement_relay_url) {
            return Err(RecoveryError::Malformed);
        }
        let proposal = Self {
            group_id: fixed(&decoded.group_id)?,
            base_epoch: decoded.base_epoch,
            base_policy_revision: decoded.base_policy_revision,
            policy_hash: fixed(&decoded.policy_hash)?,
            roster_hash: fixed(&decoded.roster_hash)?,
            receipt_head: fixed(&decoded.receipt_head)?,
            replacement_relay_url: decoded.replacement_relay_url,
            replacement_coordination_id: fixed(&decoded.replacement_coordination_id)?,
            replacement_coordinator_public_key: fixed(&decoded.replacement_coordinator_public_key)?,
            capability_set_hash: fixed(&decoded.capability_set_hash)?,
        };
        if proposal.replacement_coordination_id == [0; 32]
            || VerifyingKey::from_bytes(&proposal.replacement_coordinator_public_key).is_err()
        {
            return Err(RecoveryError::Malformed);
        }
        Ok(proposal)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryEndorsement {
    signer_identity: [u8; 32],
    signature: [u8; 64],
}

impl RecoveryEndorsement {
    pub fn sign(
        proposal: &RecoveryProposal,
        identity: &impl SecureIdentity,
    ) -> Result<Self, Error> {
        let signer_identity = identity.ensure_public_key(IdentityPurpose::Root)?;
        let signature = identity.sign(
            IdentityPurpose::GroupRecovery(proposal.group_id),
            &proposal.signing_transcript(),
        )?;
        Ok(Self {
            signer_identity,
            signature,
        })
    }

    pub fn signer_identity(&self) -> [u8; 32] {
        self.signer_identity
    }

    fn to_proto(&self) -> proto::GroupRecoveryEndorsement {
        proto::GroupRecoveryEndorsement {
            signer_identity: self.signer_identity.to_vec(),
            signature: self.signature.to_vec(),
        }
    }

    fn from_proto(value: proto::GroupRecoveryEndorsement) -> Result<Self, RecoveryError> {
        Ok(Self {
            signer_identity: fixed(&value.signer_identity)?,
            signature: value
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| RecoveryError::Malformed)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCertificate {
    proposal: RecoveryProposal,
    endorsements: Vec<RecoveryEndorsement>,
}

impl RecoveryCertificate {
    pub fn new(
        proposal: RecoveryProposal,
        mut endorsements: Vec<RecoveryEndorsement>,
    ) -> Result<Self, RecoveryError> {
        endorsements.sort_unstable_by_key(RecoveryEndorsement::signer_identity);
        if endorsements.is_empty()
            || endorsements.len() > MAX_GROUP_MEMBERS
            || endorsements
                .windows(2)
                .any(|pair| pair[0].signer_identity >= pair[1].signer_identity)
        {
            return Err(RecoveryError::Malformed);
        }
        Ok(Self {
            proposal,
            endorsements,
        })
    }

    pub fn verify(
        &self,
        policy: &PigeonGroupPolicy,
        epoch: u64,
        receipt_head: [u8; 32],
    ) -> Result<(), RecoveryError> {
        self.proposal.verify_context(policy, epoch, receipt_head)?;
        let non_owner_admins = policy
            .admins()
            .iter()
            .copied()
            .filter(|admin| *admin != policy.owner())
            .collect::<BTreeSet<_>>();
        let eligible = if non_owner_admins.is_empty() {
            BTreeSet::from([policy.owner()])
        } else {
            non_owner_admins
        };
        let required = eligible.len() / 2 + 1;
        let mut valid = 0;
        for endorsement in &self.endorsements {
            if !eligible.contains(&endorsement.signer_identity) {
                return Err(RecoveryError::UnauthorizedSigner);
            }
            let recovery_key = policy
                .member_recovery_key(endorsement.signer_identity)
                .ok_or(RecoveryError::UnauthorizedSigner)?;
            VerifyingKey::from_bytes(&recovery_key)
                .map_err(|_| RecoveryError::InvalidSignature)?
                .verify_strict(
                    &self.proposal.signing_transcript(),
                    &Signature::from_bytes(&endorsement.signature),
                )
                .map_err(|_| RecoveryError::InvalidSignature)?;
            valid += 1;
        }
        (valid >= required)
            .then_some(())
            .ok_or(RecoveryError::InsufficientQuorum)
    }

    pub fn proposal(&self) -> &RecoveryProposal {
        &self.proposal
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupRecoveryCertificate {
            version: RECOVERY_VERSION,
            proposal: Some(self.proposal.to_proto()),
            endorsements: self
                .endorsements
                .iter()
                .map(RecoveryEndorsement::to_proto)
                .collect(),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryError> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(RecoveryError::Malformed);
        }
        let decoded =
            proto::GroupRecoveryCertificate::decode(bytes).map_err(|_| RecoveryError::Malformed)?;
        if decoded.version != RECOVERY_VERSION {
            return Err(RecoveryError::Malformed);
        }
        Self::new(
            RecoveryProposal::from_proto(decoded.proposal.ok_or(RecoveryError::Malformed)?)?,
            decoded
                .endorsements
                .into_iter()
                .map(RecoveryEndorsement::from_proto)
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

pub fn relay_capability_id(
    group_id: [u8; 32],
    coordination_id: [u8; 32],
    epoch: u64,
    policy_revision: u64,
    roster_hash: [u8; 32],
    signing_public_key: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CAPABILITY_DOMAIN);
    hasher.update(group_id);
    hasher.update(coordination_id);
    hasher.update(epoch.to_be_bytes());
    hasher.update(policy_revision.to_be_bytes());
    hasher.update(roster_hash);
    hasher.update(signing_public_key);
    hasher.finalize().into()
}

fn capability_set_hash(
    policy: &PigeonGroupPolicy,
    coordination_id: [u8; 32],
    epoch: u64,
    revision: u64,
    roster_hash: [u8; 32],
) -> Result<[u8; 32], RecoveryError> {
    let mut hasher = Sha256::new();
    hasher.update(b"pigeon.relay.group.capability-set.v1");
    hasher.update((policy.members().len() as u32).to_be_bytes());
    for member in policy.members() {
        let public_key = policy
            .member_capability_key(*member)
            .ok_or(RecoveryError::InvalidContext)?;
        hasher.update(relay_capability_id(
            *policy.group_id().as_bytes(),
            coordination_id,
            epoch,
            revision,
            roster_hash,
            public_key,
        ));
        hasher.update(public_key);
    }
    Ok(hasher.finalize().into())
}

fn valid_relay(value: &str) -> bool {
    (value.starts_with("https://") || value.starts_with("wss://"))
        && !value.contains(char::is_whitespace)
        && value.len() <= 2048
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], RecoveryError> {
    bytes.try_into().map_err(|_| RecoveryError::Malformed)
}
