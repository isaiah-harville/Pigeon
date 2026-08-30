use core::fmt;

use ed25519_dalek::VerifyingKey;
use prost::Message;
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use super::{CoordinatorBinding, GroupAction, GroupId, PolicyEvent, PolicyEventKind};
use crate::identity::GroupMemberKeys;
use crate::wire::{
    MAX_GROUP_MEMBERS, MAX_GROUP_NAME_BYTES, MAX_GROUP_NAME_SCALARS, MAX_MLS_OBJECT_BYTES, proto,
};

const PROTOCOL_VERSION: u32 = 1;
const POLICY_VERSION: u32 = 2;
const MIN_GROUP_MEMBERS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PigeonGroupPolicy {
    protocol_version: u32,
    policy_version: u32,
    group_id: GroupId,
    owner: [u8; 32],
    admins: Vec<[u8; 32]>,
    members: Vec<[u8; 32]>,
    member_keys: Vec<GroupMemberKeys>,
    name: String,
    relay_url: String,
    coordination_id: [u8; 32],
    coordinator_public_key: [u8; 32],
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
    pub(crate) fn validate_draft(
        owner: [u8; 32],
        mut additional_members: Vec<[u8; 32]>,
        name: &str,
        relay_url: &str,
        coordinator: CoordinatorBinding,
    ) -> Result<(), PolicyError> {
        additional_members.push(owner);
        additional_members.sort_unstable();
        if additional_members.len() < MIN_GROUP_MEMBERS
            || additional_members.len() > MAX_GROUP_MEMBERS
            || !is_sorted_unique(&additional_members)
        {
            return Err(PolicyError::InvalidRoster);
        }
        validate_name(name)?;
        validate_relay(relay_url)?;
        if coordinator.public_key == [0; 32]
            || VerifyingKey::from_bytes(&coordinator.public_key).is_err()
        {
            return Err(PolicyError::InvalidRelay);
        }
        Ok(())
    }

    pub fn new(
        group_id: GroupId,
        owner: [u8; 32],
        member_keys: Vec<GroupMemberKeys>,
        name: impl Into<String>,
        relay_url: impl Into<String>,
        coordinator: CoordinatorBinding,
    ) -> Result<Self, PolicyError> {
        Self::new_with_mesh(
            group_id,
            owner,
            member_keys,
            name,
            relay_url,
            coordinator,
            false,
        )
    }

    pub(crate) fn new_with_mesh(
        group_id: GroupId,
        owner: [u8; 32],
        mut member_keys: Vec<GroupMemberKeys>,
        name: impl Into<String>,
        relay_url: impl Into<String>,
        coordinator: CoordinatorBinding,
        mesh_enabled: bool,
    ) -> Result<Self, PolicyError> {
        member_keys.sort_unstable_by_key(GroupMemberKeys::member_identity);
        let members = member_keys
            .iter()
            .map(GroupMemberKeys::member_identity)
            .collect();
        let policy = Self {
            protocol_version: PROTOCOL_VERSION,
            policy_version: POLICY_VERSION,
            group_id,
            owner,
            admins: vec![owner],
            members,
            member_keys,
            name: name.into(),
            relay_url: relay_url.into(),
            coordination_id: coordinator.coordination_id,
            coordinator_public_key: coordinator.public_key,
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
            member_keys: encoded
                .member_keys
                .into_iter()
                .map(GroupMemberKeys::from_proto)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| PolicyError::Malformed)?,
            name: encoded.name,
            relay_url: encoded.relay_url,
            coordination_id: to_identity(&encoded.coordination_id)?,
            coordinator_public_key: to_identity(&encoded.coordinator_public_key)?,
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

    pub fn coordinator_public_key(&self) -> [u8; 32] {
        self.coordinator_public_key
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
            let member_keys = candidate
                .member_keys
                .iter()
                .find(|keys| keys.member_identity() == added_members[0])
                .cloned()
                .ok_or(PolicyError::UnexpectedTransition)?;
            GroupAction::Add {
                actor,
                member_keys: Box::new(member_keys),
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

    pub fn member_capability_key(&self, identity: [u8; 32]) -> Option<[u8; 32]> {
        self.member_keys
            .binary_search_by_key(&identity, GroupMemberKeys::member_identity)
            .ok()
            .map(|index| self.member_keys[index].capability_public_key())
    }

    pub(crate) fn relay_capability_delta(
        &self,
        next: &Self,
        event: &PolicyEvent,
    ) -> Result<Option<(bool, [u8; 32])>, PolicyError> {
        if self.group_id != next.group_id
            || self.coordination_id != next.coordination_id
            || event.revision != next.revision
        {
            return Err(PolicyError::UnexpectedTransition);
        }
        let action = match event.kind {
            PolicyEventKind::MemberAdded => {
                let subject = event.subject.ok_or(PolicyError::UnexpectedTransition)?;
                let member_keys = next
                    .member_keys
                    .iter()
                    .find(|keys| keys.member_identity() == subject)
                    .cloned()
                    .ok_or(PolicyError::UnexpectedTransition)?;
                GroupAction::Add {
                    actor: event.actor,
                    member_keys: Box::new(member_keys),
                }
            }
            PolicyEventKind::MemberRemoved => GroupAction::Remove {
                actor: event.actor,
                subject: event.subject.ok_or(PolicyError::UnexpectedTransition)?,
            },
            PolicyEventKind::MemberLeft => {
                let departing = event.subject.ok_or(PolicyError::UnexpectedTransition)?;
                let committer = next
                    .members
                    .iter()
                    .find(|identity| **identity != departing)
                    .copied()
                    .ok_or(PolicyError::UnexpectedTransition)?;
                GroupAction::Leave {
                    actor: departing,
                    committer,
                }
            }
            PolicyEventKind::AdminPromoted => GroupAction::Promote {
                actor: event.actor,
                subject: event.subject.ok_or(PolicyError::UnexpectedTransition)?,
            },
            PolicyEventKind::AdminDemoted => GroupAction::Demote {
                actor: event.actor,
                subject: event.subject.ok_or(PolicyError::UnexpectedTransition)?,
            },
            PolicyEventKind::NameChanged => GroupAction::Rename {
                actor: event.actor,
                name: next.name.clone(),
            },
            PolicyEventKind::MeshChanged => GroupAction::SetMesh {
                actor: event.actor,
                enabled: next.mesh_enabled,
            },
            PolicyEventKind::RelayChanged => GroupAction::SetRelay {
                actor: event.actor,
                relay_url: next.relay_url.clone(),
            },
            PolicyEventKind::Dissolved => GroupAction::Dissolve { actor: event.actor },
        };
        let (expected, expected_event) = self.apply(&action)?;
        if expected != *next || expected_event != *event {
            return Err(PolicyError::UnexpectedTransition);
        }
        match event.kind {
            PolicyEventKind::MemberAdded => Ok(Some((
                true,
                next.member_capability_key(event.subject.ok_or(PolicyError::UnexpectedTransition)?)
                    .ok_or(PolicyError::UnexpectedTransition)?,
            ))),
            PolicyEventKind::MemberRemoved | PolicyEventKind::MemberLeft => Ok(Some((
                false,
                self.member_capability_key(event.subject.ok_or(PolicyError::UnexpectedTransition)?)
                    .ok_or(PolicyError::UnexpectedTransition)?,
            ))),
            _ => Ok(None),
        }
    }

    pub(crate) fn can_invite(&self, actor: [u8; 32], subject: [u8; 32]) -> Result<(), PolicyError> {
        self.validate_invariants()?;
        self.require_admin(&actor)?;
        if self.dissolved
            || self.members.len() >= MAX_GROUP_MEMBERS
            || self.has_member(&subject)
            || VerifyingKey::from_bytes(&subject).is_err()
        {
            return Err(PolicyError::InvalidRoster);
        }
        Ok(())
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
            coordinator_public_key: self.coordinator_public_key.to_vec(),
            member_keys: self
                .member_keys
                .iter()
                .map(GroupMemberKeys::to_proto)
                .collect(),
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
            || self.member_keys.len() != self.members.len()
            || self
                .member_keys
                .iter()
                .map(GroupMemberKeys::member_identity)
                .ne(self.members.iter().copied())
            || !self.has_member(&self.owner)
            || !self.has_admin(&self.owner)
            || self.admins.iter().any(|admin| !self.has_member(admin))
        {
            return Err(PolicyError::InvalidRoster);
        }
        if self.member_keys.iter().any(|keys| {
            keys.verify(self.owner, self.group_id, self.coordination_id)
                .is_err()
        }) || !is_unique_keys(
            self.member_keys
                .iter()
                .map(GroupMemberKeys::capability_public_key),
        ) || !is_unique_keys(
            self.member_keys
                .iter()
                .map(GroupMemberKeys::recovery_public_key),
        ) {
            return Err(PolicyError::InvalidRoster);
        }
        validate_name(&self.name)?;
        validate_relay(&self.relay_url)?;
        if self.coordinator_public_key == [0; 32]
            || VerifyingKey::from_bytes(&self.coordinator_public_key).is_err()
        {
            return Err(PolicyError::InvalidRelay);
        }
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
        GroupAction::Add { actor, member_keys } => {
            prior.require_admin(actor)?;
            let subject = member_keys.member_identity();
            if next.members.len() >= MAX_GROUP_MEMBERS || next.has_member(&subject) {
                return Err(PolicyError::InvalidRoster);
            }
            member_keys
                .verify(prior.owner, prior.group_id, prior.coordination_id)
                .map_err(|_| PolicyError::InvalidRoster)?;
            next.members.push(subject);
            next.members.sort_unstable();
            next.member_keys.push((**member_keys).clone());
            next.member_keys
                .sort_unstable_by_key(GroupMemberKeys::member_identity);
            (PolicyEventKind::MemberAdded, *actor, Some(subject))
        }
        GroupAction::Remove { actor, subject } => {
            prior.require_admin(actor)?;
            if actor == subject || *subject == prior.owner || !prior.has_member(subject) {
                return Err(PolicyError::Unauthorized);
            }
            require_can_shrink(&next)?;
            remove_identity(&mut next.members, subject);
            remove_identity(&mut next.admins, subject);
            remove_member_keys(&mut next.member_keys, subject);
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
            remove_member_keys(&mut next.member_keys, actor);
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

fn remove_member_keys(keys: &mut Vec<GroupMemberKeys>, identity: &[u8; 32]) {
    if let Ok(index) = keys.binary_search_by_key(identity, GroupMemberKeys::member_identity) {
        keys.remove(index);
    }
}

fn is_unique_keys(keys: impl Iterator<Item = [u8; 32]>) -> bool {
    let mut keys = keys.collect::<Vec<_>>();
    keys.sort_unstable();
    is_sorted_unique(&keys)
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
