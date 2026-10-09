impl PigeonGroupPolicy {
    pub(crate) fn relay_capability_delta(
        &self,
        next: &Self,
        event: &PolicyEvent,
    ) -> Result<Option<(RelayCapabilityDelta, [u8; 32])>, PolicyError> {
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
                    .admins
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
                RelayCapabilityDelta::Grant,
                next.member_capability_key(event.subject.ok_or(PolicyError::UnexpectedTransition)?)
                    .ok_or(PolicyError::UnexpectedTransition)?,
            ))),
            PolicyEventKind::MemberRemoved | PolicyEventKind::MemberLeft => Ok(Some((
                RelayCapabilityDelta::Revoke,
                self.member_capability_key(event.subject.ok_or(PolicyError::UnexpectedTransition)?)
                    .ok_or(PolicyError::UnexpectedTransition)?,
            ))),
            PolicyEventKind::AdminPromoted => Ok(Some((
                RelayCapabilityDelta::PromoteAdmin,
                next.member_capability_key(event.subject.ok_or(PolicyError::UnexpectedTransition)?)
                    .ok_or(PolicyError::UnexpectedTransition)?,
            ))),
            PolicyEventKind::AdminDemoted => Ok(Some((
                RelayCapabilityDelta::DemoteAdmin,
                next.member_capability_key(event.subject.ok_or(PolicyError::UnexpectedTransition)?)
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
        if self
            .member_keys
            .iter()
            .any(|keys| keys.verify(self.owner, self.group_id).is_err())
            || !is_unique_keys(
                self.member_keys
                    .iter()
                    .map(GroupMemberKeys::capability_public_key),
            )
            || !is_unique_keys(
                self.member_keys
                    .iter()
                    .map(GroupMemberKeys::recovery_public_key),
            )
        {
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
                .verify(prior.owner, prior.group_id)
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
                || !prior.has_admin(committer)
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
