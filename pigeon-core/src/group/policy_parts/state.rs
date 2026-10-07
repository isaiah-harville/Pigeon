pub(crate) enum RelayCapabilityDelta {
    Grant,
    Revoke,
    PromoteAdmin,
    DemoteAdmin,
}

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

    pub(crate) fn recover(
        &self,
        candidate: &Self,
        actor: [u8; 32],
        certificate: &RecoveryCertificate,
    ) -> Result<PolicyEvent, PolicyError> {
        self.validate_invariants()?;
        candidate.validate_invariants()?;
        self.require_admin(&actor)?;
        let proposal = certificate.proposal();
        if proposal.group_id() != *self.group_id.as_bytes()
            || candidate.group_id != self.group_id
            || candidate.owner != self.owner
            || candidate.admins != self.admins
            || candidate.members != self.members
            || candidate.member_keys != self.member_keys
            || candidate.name != self.name
            || candidate.mesh_enabled != self.mesh_enabled
            || candidate.dissolved != self.dissolved
            || candidate.revision
                != self
                    .revision
                    .checked_add(1)
                    .ok_or(PolicyError::InvalidRevision)?
            || candidate.relay_url != proposal.replacement_relay_url()
            || candidate.coordination_id != proposal.replacement().coordination_id
            || candidate.coordinator_public_key != proposal.replacement().public_key
        {
            return Err(PolicyError::UnexpectedTransition);
        }
        Ok(PolicyEvent {
            kind: PolicyEventKind::RelayChanged,
            actor,
            subject: None,
            revision: candidate.revision,
        })
    }

    pub(crate) fn recovered_policy(
        &self,
        actor: [u8; 32],
        certificate: &RecoveryCertificate,
    ) -> Result<(Self, PolicyEvent), PolicyError> {
        self.require_admin(&actor)?;
        let mut candidate = self.clone();
        candidate.relay_url = certificate.proposal().replacement_relay_url().to_owned();
        candidate.coordination_id = certificate.proposal().replacement().coordination_id;
        candidate.coordinator_public_key = certificate.proposal().replacement().public_key;
        candidate.revision = self
            .revision
            .checked_add(1)
            .ok_or(PolicyError::InvalidRevision)?;
        let event = self.recover(&candidate, actor, certificate)?;
        Ok((candidate, event))
    }

    pub(crate) fn can_leave(&self, actor: [u8; 32]) -> Result<(), PolicyError> {
        let committer = self
            .admins
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

    pub fn admins(&self) -> &[[u8; 32]] {
        &self.admins
    }

    pub fn is_admin(&self, identity: [u8; 32]) -> bool {
        self.admins.binary_search(&identity).is_ok()
    }

    pub(crate) fn can_endorse_recovery(&self, identity: [u8; 32]) -> bool {
        let has_non_owner_admin = self.admins.iter().any(|admin| *admin != self.owner);
        if has_non_owner_admin {
            identity != self.owner && self.is_admin(identity)
        } else {
            identity == self.owner
        }
    }

    pub fn member_capability_key(&self, identity: [u8; 32]) -> Option<[u8; 32]> {
        self.member_keys
            .binary_search_by_key(&identity, GroupMemberKeys::member_identity)
            .ok()
            .map(|index| self.member_keys[index].capability_public_key())
    }

    pub fn member_recovery_key(&self, identity: [u8; 32]) -> Option<[u8; 32]> {
        self.member_keys
            .binary_search_by_key(&identity, GroupMemberKeys::member_identity)
            .ok()
            .map(|index| self.member_keys[index].recovery_public_key())
    }

    pub fn policy_hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    pub fn roster_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"pigeon.group.roster.v1");
        hasher.update((self.members.len() as u32).to_be_bytes());
        for member in &self.members {
            hasher.update(member);
        }
        hasher.finalize().into()
    }

}
