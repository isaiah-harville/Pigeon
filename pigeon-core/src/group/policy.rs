use core::fmt;

use prost::Message;
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use super::{GroupAction, GroupId, PolicyEvent, PolicyEventKind};
use crate::wire::{
    MAX_GROUP_MEMBERS, MAX_GROUP_NAME_BYTES, MAX_GROUP_NAME_SCALARS, MAX_MLS_OBJECT_BYTES, proto,
};

const PROTOCOL_VERSION: u32 = 1;
const POLICY_VERSION: u32 = 1;
const MIN_GROUP_MEMBERS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PigeonGroupPolicy {
    protocol_version: u32,
    policy_version: u32,
    group_id: GroupId,
    owner: [u8; 32],
    admins: Vec<[u8; 32]>,
    members: Vec<[u8; 32]>,
    name: String,
    relay_url: String,
    coordination_id: [u8; 32],
    mesh_enabled: bool,
    revision: u64,
    dissolved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    Unauthorized,
    InvalidRoster,
    InvalidName,
    InvalidRelay,
    InvalidRevision,
    UnsupportedVersion,
    Terminal,
    NoChange,
    UnexpectedTransition,
    Malformed,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "group policy validation failed: {self:?}")
    }
}

impl std::error::Error for PolicyError {}

impl PigeonGroupPolicy {
    pub fn new(
        group_id: GroupId,
        owner: [u8; 32],
        additional_members: Vec<[u8; 32]>,
        name: impl Into<String>,
        relay_url: impl Into<String>,
        coordination_id: [u8; 32],
    ) -> Result<Self, PolicyError> {
        Self::new_with_mesh(
            group_id,
            owner,
            additional_members,
            name,
            relay_url,
            coordination_id,
            false,
        )
    }

    pub(crate) fn new_with_mesh(
        group_id: GroupId,
        owner: [u8; 32],
        additional_members: Vec<[u8; 32]>,
        name: impl Into<String>,
        relay_url: impl Into<String>,
        coordination_id: [u8; 32],
        mesh_enabled: bool,
    ) -> Result<Self, PolicyError> {
        let mut members = additional_members;
        members.push(owner);
        members.sort_unstable();
        let policy = Self {
            protocol_version: PROTOCOL_VERSION,
            policy_version: POLICY_VERSION,
            group_id,
            owner,
            admins: vec![owner],
            members,
            name: name.into(),
            relay_url: relay_url.into(),
            coordination_id,
            mesh_enabled,
            revision: 0,
            dissolved: false,
        };
        policy.validate_invariants()?;
        Ok(policy)
    }

    pub fn apply(&self, action: &GroupAction) -> Result<(Self, PolicyEvent), PolicyError> {
        transition_body(self, action)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(PolicyError::Malformed);
        }
        let encoded =
            proto::PigeonGroupPolicy::decode(bytes).map_err(|_| PolicyError::Malformed)?;
        let policy = Self {
            protocol_version: encoded.protocol_version,
            policy_version: encoded.policy_version,
            group_id: GroupId::from_bytes(to_identity(&encoded.group_id)?),
            owner: to_identity(&encoded.owner_identity)?,
            admins: identities(encoded.admin_identities)?,
            members: identities(encoded.member_identities)?,
            name: encoded.name,
            relay_url: encoded.relay_url,
            coordination_id: to_identity(&encoded.coordination_id)?,
            mesh_enabled: encoded.mesh_enabled,
            revision: encoded.revision,
            dissolved: encoded.dissolved,
        };
        policy.validate_invariants()?;
        Ok(policy)
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn owner(&self) -> [u8; 32] {
        self.owner
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    pub fn coordination_id(&self) -> [u8; 32] {
        self.coordination_id
    }

    pub fn mesh_enabled(&self) -> bool {
        self.mesh_enabled
    }

    pub fn dissolved(&self) -> bool {
        self.dissolved
    }

    pub(crate) fn authenticate_candidate(
        &self,
        candidate: &Self,
        actor: [u8; 32],
    ) -> Result<PolicyEvent, PolicyError> {
        let added_members = difference(&candidate.members, &self.members);
        let removed_members = difference(&self.members, &candidate.members);
        let added_admins = difference(&candidate.admins, &self.admins);
        let removed_admins = difference(&self.admins, &candidate.admins);
        let action = if added_members.len() == 1 && removed_members.is_empty() {
            GroupAction::Add {
                actor,
                subject: added_members[0],
            }
        } else if removed_members.len() == 1 && added_members.is_empty() {
            GroupAction::Remove {
                actor,
                subject: removed_members[0],
            }
        } else if added_admins.len() == 1 && removed_admins.is_empty() {
            GroupAction::Promote {
                actor,
                subject: added_admins[0],
            }
        } else if removed_admins.len() == 1 && added_admins.is_empty() {
            GroupAction::Demote {
                actor,
                subject: removed_admins[0],
            }
        } else if self.name != candidate.name {
            GroupAction::Rename {
                actor,
                name: candidate.name.clone(),
            }
        } else if self.mesh_enabled != candidate.mesh_enabled {
            GroupAction::SetMesh {
                actor,
                enabled: candidate.mesh_enabled,
            }
        } else if self.relay_url != candidate.relay_url {
            GroupAction::SetRelay {
                actor,
                relay_url: candidate.relay_url.clone(),
            }
        } else if !self.dissolved && candidate.dissolved {
            GroupAction::Dissolve { actor }
        } else {
            return Err(PolicyError::UnexpectedTransition);
        };
        validate_transition(self, candidate, &action)
    }

    pub(crate) fn authenticate_action(
        &self,
        candidate: &Self,
        action: &GroupAction,
    ) -> Result<PolicyEvent, PolicyError> {
        validate_transition(self, candidate, action)
    }

    pub(crate) fn can_leave(&self, actor: [u8; 32]) -> Result<(), PolicyError> {
        let committer = self
            .members
            .iter()
            .copied()
            .find(|member| *member != actor)
            .ok_or(PolicyError::InvalidRoster)?;
        self.apply(&GroupAction::Leave { actor, committer })
            .map(|_| ())
    }

    pub fn members(&self) -> &[[u8; 32]] {
        &self.members
    }

    fn to_proto(&self) -> proto::PigeonGroupPolicy {
        proto::PigeonGroupPolicy {
            protocol_version: self.protocol_version,
            policy_version: self.policy_version,
            group_id: self.group_id.as_bytes().to_vec(),
            owner_identity: self.owner.to_vec(),
            admin_identities: self
                .admins
                .iter()
                .map(|identity| identity.to_vec())
                .collect(),
            member_identities: self
                .members
                .iter()
                .map(|identity| identity.to_vec())
                .collect(),
            name: self.name.clone(),
            relay_url: self.relay_url.clone(),
            coordination_id: self.coordination_id.to_vec(),
            mesh_enabled: self.mesh_enabled,
            revision: self.revision,
            dissolved: self.dissolved,
        }
    }

    fn validate_invariants(&self) -> Result<(), PolicyError> {
        if self.protocol_version != PROTOCOL_VERSION || self.policy_version != POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion);
        }
        if self.members.len() < MIN_GROUP_MEMBERS
            || self.members.len() > MAX_GROUP_MEMBERS
            || !is_sorted_unique(&self.members)
            || !is_sorted_unique(&self.admins)
            || !self.has_member(&self.owner)
            || !self.has_admin(&self.owner)
            || self.admins.iter().any(|admin| !self.has_member(admin))
        {
            return Err(PolicyError::InvalidRoster);
        }
        validate_name(&self.name)?;
        validate_relay(&self.relay_url)?;
        Ok(())
    }

    fn require_owner(&self, actor: &[u8; 32]) -> Result<(), PolicyError> {
        (actor == &self.owner)
            .then_some(())
            .ok_or(PolicyError::Unauthorized)
    }

    fn require_admin(&self, actor: &[u8; 32]) -> Result<(), PolicyError> {
        self.has_admin(actor)
            .then_some(())
            .ok_or(PolicyError::Unauthorized)
    }

    fn has_member(&self, identity: &[u8; 32]) -> bool {
        self.members.binary_search(identity).is_ok()
    }

    fn has_admin(&self, identity: &[u8; 32]) -> bool {
        self.admins.binary_search(identity).is_ok()
    }
}

pub fn validate_transition(
    prior: &PigeonGroupPolicy,
    next: &PigeonGroupPolicy,
    action: &GroupAction,
) -> Result<PolicyEvent, PolicyError> {
    prior.validate_invariants()?;
    next.validate_invariants()?;
    if next.revision
        != prior
            .revision
            .checked_add(1)
            .ok_or(PolicyError::InvalidRevision)?
    {
        return Err(PolicyError::InvalidRevision);
    }
    let (expected, event) = transition_body(prior, action)?;
    if &expected == next {
        Ok(event)
    } else {
        Err(PolicyError::UnexpectedTransition)
    }
}

fn transition_body(
    prior: &PigeonGroupPolicy,
    action: &GroupAction,
) -> Result<(PigeonGroupPolicy, PolicyEvent), PolicyError> {
    if prior.dissolved {
        return Err(PolicyError::Terminal);
    }
    prior.validate_invariants()?;
    let mut next = prior.clone();
    let (kind, actor, subject) = match action {
        GroupAction::Add { actor, subject } => {
            prior.require_admin(actor)?;
            if next.members.len() >= MAX_GROUP_MEMBERS || next.has_member(subject) {
                return Err(PolicyError::InvalidRoster);
            }
            next.members.push(*subject);
            next.members.sort_unstable();
            (PolicyEventKind::MemberAdded, *actor, Some(*subject))
        }
        GroupAction::Remove { actor, subject } => {
            prior.require_admin(actor)?;
            if actor == subject || *subject == prior.owner || !prior.has_member(subject) {
                return Err(PolicyError::Unauthorized);
            }
            require_can_shrink(&next)?;
            remove_identity(&mut next.members, subject);
            remove_identity(&mut next.admins, subject);
            (PolicyEventKind::MemberRemoved, *actor, Some(*subject))
        }
        GroupAction::Leave { actor, committer } => {
            if *actor == prior.owner
                || actor == committer
                || !prior.has_member(actor)
                || !prior.has_member(committer)
            {
                return Err(PolicyError::Unauthorized);
            }
            require_can_shrink(&next)?;
            remove_identity(&mut next.members, actor);
            remove_identity(&mut next.admins, actor);
            (PolicyEventKind::MemberLeft, *actor, Some(*actor))
        }
        GroupAction::Promote { actor, subject } => {
            prior.require_admin(actor)?;
            if !prior.has_member(subject) || prior.has_admin(subject) {
                return Err(PolicyError::InvalidRoster);
            }
            next.admins.push(*subject);
            next.admins.sort_unstable();
            (PolicyEventKind::AdminPromoted, *actor, Some(*subject))
        }
        GroupAction::Demote { actor, subject } => {
            prior.require_admin(actor)?;
            if actor == subject || *subject == prior.owner || !prior.has_admin(subject) {
                return Err(PolicyError::Unauthorized);
            }
            remove_identity(&mut next.admins, subject);
            (PolicyEventKind::AdminDemoted, *actor, Some(*subject))
        }
        GroupAction::Rename { actor, name } => {
            prior.require_owner(actor)?;
            if &prior.name == name {
                return Err(PolicyError::NoChange);
            }
            next.name = name.clone();
            (PolicyEventKind::NameChanged, *actor, None)
        }
        GroupAction::SetMesh { actor, enabled } => {
            prior.require_owner(actor)?;
            if prior.mesh_enabled == *enabled {
                return Err(PolicyError::NoChange);
            }
            next.mesh_enabled = *enabled;
            (PolicyEventKind::MeshChanged, *actor, None)
        }
        GroupAction::SetRelay { actor, relay_url } => {
            prior.require_owner(actor)?;
            if &prior.relay_url == relay_url {
                return Err(PolicyError::NoChange);
            }
            next.relay_url = relay_url.clone();
            (PolicyEventKind::RelayChanged, *actor, None)
        }
        GroupAction::Dissolve { actor } => {
            prior.require_owner(actor)?;
            next.dissolved = true;
            (PolicyEventKind::Dissolved, *actor, None)
        }
    };
    next.revision = prior
        .revision
        .checked_add(1)
        .ok_or(PolicyError::InvalidRevision)?;
    next.validate_invariants()?;
    let event = PolicyEvent {
        kind,
        actor,
        subject,
        revision: next.revision,
    };
    Ok((next, event))
}

fn require_can_shrink(policy: &PigeonGroupPolicy) -> Result<(), PolicyError> {
    (policy.members.len() > MIN_GROUP_MEMBERS)
        .then_some(())
        .ok_or(PolicyError::InvalidRoster)
}

fn validate_name(name: &str) -> Result<(), PolicyError> {
    let normalized: String = name.nfc().collect();
    let has_noncanonical_whitespace = name
        .chars()
        .any(|character| character.is_whitespace() && character != ' ')
        || name.contains("  ");
    let has_disallowed_category = name.chars().any(|character| {
        matches!(
            get_general_category(character),
            GeneralCategory::Control | GeneralCategory::Format
        )
    });
    if name.is_empty()
        || name.len() > MAX_GROUP_NAME_BYTES
        || name.chars().count() > MAX_GROUP_NAME_SCALARS
        || name != normalized
        || name.trim() != name
        || has_noncanonical_whitespace
        || has_disallowed_category
    {
        Err(PolicyError::InvalidName)
    } else {
        Ok(())
    }
}

fn validate_relay(relay: &str) -> Result<(), PolicyError> {
    if relay.len() > 2048 || !(relay.starts_with("https://") || relay.starts_with("wss://")) {
        Err(PolicyError::InvalidRelay)
    } else {
        Ok(())
    }
}

fn is_sorted_unique(identities: &[[u8; 32]]) -> bool {
    identities.windows(2).all(|pair| pair[0] < pair[1])
}

fn remove_identity(identities: &mut Vec<[u8; 32]>, identity: &[u8; 32]) {
    if let Ok(index) = identities.binary_search(identity) {
        identities.remove(index);
    }
}

fn difference(left: &[[u8; 32]], right: &[[u8; 32]]) -> Vec<[u8; 32]> {
    left.iter()
        .filter(|identity| right.binary_search(identity).is_err())
        .copied()
        .collect()
}

fn identities(values: Vec<Vec<u8>>) -> Result<Vec<[u8; 32]>, PolicyError> {
    values
        .into_iter()
        .map(|value| to_identity(&value))
        .collect()
}

fn to_identity(value: &[u8]) -> Result<[u8; 32], PolicyError> {
    value.try_into().map_err(|_| PolicyError::Malformed)
}
