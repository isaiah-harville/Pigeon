use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, Serialize};

use super::{
    AuthenticatedGroupMessage, CoordinatorBinding, GroupAction, GroupApplication, GroupCiphertext,
    GroupId, GroupMessageId, PendingMutation, PigeonGroupPolicy, PolicyEvent,
};
use crate::Error;
use crate::identity::{
    CIPHERSUITE, GroupJoinMaterial, GroupMemberKeys, MlsIdentityBinding, POLICY_EXTENSION_TYPE_ID,
    PlatformMlsSigner, SecureIdentity,
};
use crate::storage::TransactionalOpenMlsStorage;
use crate::wire::{MAX_FUTURE_EPOCHS, MAX_MLS_OBJECT_BYTES};

#[derive(Clone, Debug)]
pub struct GroupEngine {
    group_id: GroupId,
    policy: PigeonGroupPolicy,
    epoch: u64,
    pending: Option<PendingMutation>,
}

pub struct GroupCreationConfig {
    pub group_id: GroupId,
    pub name: String,
    pub relay_url: String,
    pub coordinator: CoordinatorBinding,
    pub mesh_enabled: bool,
}

impl GroupEngine {
    pub(crate) fn restore(
        storage: &TransactionalOpenMlsStorage,
        policy: PigeonGroupPolicy,
        expected_epoch: u64,
    ) -> Result<Self, Error> {
        let group = load_group(storage.provider(), policy.group_id())?;
        verify_group_policy(&group, &policy)?;
        if group.epoch().as_u64() != expected_epoch {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            group_id: policy.group_id(),
            policy,
            epoch: expected_epoch,
            pending: None,
        })
    }

    pub fn encrypt_application<I: SecureIdentity>(
        &mut self,
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        application: GroupApplication,
    ) -> Result<GroupCiphertext, Error> {
        let sender = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        if !self.policy.members().contains(&sender) || self.policy.dissolved() {
            return Err(Error::InvalidSignature);
        }
        let mut message_id = [0_u8; 16];
        getrandom::getrandom(&mut message_id).map_err(|_| Error::Entropy)?;
        let message_id = GroupMessageId::from_bytes(message_id);
        let plaintext = super::message::encode_content(
            self.group_id,
            self.epoch,
            sender,
            message_id,
            application,
        )?;
        let provider = storage.provider();
        let signer = PlatformMlsSigner(identity);
        let mut group = load_group(provider, self.group_id)?;
        let credential = group.credential().map_err(|_| Error::InvalidKey)?;
        if binding_from_credential(credential)?.root_public_key() != sender {
            return Err(Error::InvalidSignature);
        }
        let ciphertext = group
            .create_message(provider, &signer, &plaintext)
            .map_err(|_| Error::Mls("encrypt group application"))?
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)?;
        Ok(GroupCiphertext::new(
            self.group_id,
            self.epoch,
            message_id,
            ciphertext,
        ))
    }

    pub fn decrypt_application(
        &mut self,
        storage: &mut TransactionalOpenMlsStorage,
        ciphertext: &GroupCiphertext,
    ) -> Result<AuthenticatedGroupMessage, Error> {
        if ciphertext.group_id() != self.group_id
            || ciphertext.epoch() > self.epoch
            || self.epoch.saturating_sub(ciphertext.epoch()) > MAX_FUTURE_EPOCHS as u64
        {
            return Err(Error::InvalidSignature);
        }
        if ciphertext.ciphertext().len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("MLS application bytes"));
        }
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext.ciphertext())
            .map_err(|_| Error::Serialization)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| Error::Serialization)?;
        let processed = group
            .process_message(provider, protocol_message)
            .map_err(|_| Error::Mls("decrypt group application"))?;
        let sender = binding_from_credential(processed.credential())?.root_public_key();
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            return Err(Error::Mls("group input was not an application message"));
        };
        super::message::decode_content(&application.into_bytes(), ciphertext, sender)
    }

    pub fn create<I: SecureIdentity>(
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        config: GroupCreationConfig,
        materials: Vec<GroupJoinMaterial>,
    ) -> Result<(Self, Vec<u8>), Error> {
        let (engine, _, welcome) = Self::create_configured(identity, storage, config, materials)?;
        Ok((engine, welcome))
    }

    pub(crate) fn create_configured<I: SecureIdentity>(
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        config: GroupCreationConfig,
        materials: Vec<GroupJoinMaterial>,
    ) -> Result<(Self, Vec<u8>, Vec<u8>), Error> {
        let owner = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        let mut member_keys = Vec::with_capacity(materials.len() + 1);
        member_keys.push(GroupMemberKeys::issue(
            identity,
            owner,
            config.group_id,
            config.coordinator.coordination_id,
        )?);
        let mut key_packages = Vec::with_capacity(materials.len());
        for material in materials {
            material.verify_for(owner, config.group_id, config.coordinator.coordination_id)?;
            member_keys.push(material.member_keys());
            key_packages.push(material.key_package().validated_key_package()?);
        }

        let policy = PigeonGroupPolicy::new_with_mesh(
            config.group_id,
            owner,
            member_keys,
            config.name,
            config.relay_url,
            config.coordinator,
            config.mesh_enabled,
        )?;
        let binding = MlsIdentityBinding::create(identity)?;
        let signer = PlatformMlsSigner(identity);
        let provider = storage.provider();
        let mut group = MlsGroup::builder()
            .with_group_id(openmls::prelude::GroupId::from_slice(
                config.group_id.as_bytes(),
            ))
            .ciphersuite(CIPHERSUITE)
            .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .with_capabilities(policy_capabilities())
            .with_group_context_extensions(policy_extensions(&policy)?)
            .max_past_epochs(MAX_FUTURE_EPOCHS)
            .build(provider, &signer, binding.credential_with_key())
            .map_err(|_| Error::Mls("create group"))?;

        let bundle = group
            .commit_builder()
            .propose_adds(key_packages)
            .load_psks(provider.storage())
            .map_err(|_| Error::Mls("load pre-shared keys"))?
            .build(provider.rand(), provider.crypto(), &signer, |_| true)
            .map_err(|_| Error::Mls("build initial member commit"))?
            .stage_commit(provider)
            .map_err(|_| Error::Mls("stage initial member commit"))?;
        let welcome = bundle
            .to_welcome_msg()
            .ok_or(Error::Mls("create initial Welcome"))?
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)?;
        let initial_commit = bundle
            .commit()
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)?;
        group
            .merge_pending_commit(provider)
            .map_err(|_| Error::Mls("merge initial member commit"))?;
        verify_group_policy(&group, &policy)?;

        Ok((
            Self {
                group_id: config.group_id,
                policy,
                epoch: group.epoch().as_u64(),
                pending: None,
            },
            initial_commit,
            welcome,
        ))
    }

    pub fn join_welcome<I: SecureIdentity>(
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        welcome: &[u8],
    ) -> Result<Self, Error> {
        if welcome.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("MLS Welcome bytes"));
        }
        let message =
            MlsMessageIn::tls_deserialize_exact(welcome).map_err(|_| Error::Serialization)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(Error::Serialization);
        };
        let join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(MAX_FUTURE_EPOCHS)
            .build();
        let staged =
            StagedWelcome::new_from_welcome(storage.provider(), &join_config, welcome, None)
                .map_err(|_| Error::Mls("stage Welcome"))?;
        let policy = policy_from_extensions(staged.group_context().extensions())?;
        verify_staged_roster(&staged, &policy)?;
        let local_root = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        let own_binding = binding_from_credential(
            staged
                .own_leaf_node()
                .ok_or(Error::Mls("missing own MLS leaf"))?
                .credential(),
        )?;
        if own_binding.root_public_key() != local_root {
            return Err(Error::InvalidSignature);
        }
        let mls_group_id = staged.group_context().group_id().as_slice();
        if mls_group_id != policy.group_id().as_bytes() {
            return Err(Error::InvalidSignature);
        }
        let group = staged
            .into_group(storage.provider())
            .map_err(|_| Error::Mls("join Welcome"))?;
        Ok(Self {
            group_id: policy.group_id(),
            policy,
            epoch: group.epoch().as_u64(),
            pending: None,
        })
    }

    pub fn stage_candidate<I: SecureIdentity>(
        &mut self,
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        action: GroupAction,
        join_material: Option<GroupJoinMaterial>,
    ) -> Result<PendingMutation, Error> {
        if self.pending.is_some() {
            return Err(Error::Mls("candidate already pending"));
        }
        if matches!(action, GroupAction::Leave { .. }) {
            return Err(Error::Mls("leave requires a signed self-remove proposal"));
        }
        let local_root = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        if action_actor(&action) != local_root {
            return Err(Error::InvalidSignature);
        }
        let (candidate, event) = self.policy.apply(&action)?;
        let signer = PlatformMlsSigner(identity);
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        let (add, remove) = match &action {
            GroupAction::Add { member_keys, .. } => {
                let material = join_material.ok_or(Error::InvalidKey)?;
                material.verify_for(
                    self.policy.owner(),
                    self.group_id,
                    self.policy.coordination_id(),
                )?;
                if material.member_keys() != **member_keys {
                    return Err(Error::InvalidSignature);
                }
                (Some(material.key_package().validated_key_package()?), None)
            }
            GroupAction::Remove { subject, .. } | GroupAction::Leave { actor: subject, .. } => {
                if join_material.is_some() {
                    return Err(Error::InvalidKey);
                }
                (None, Some(member_index(&group, *subject)?))
            }
            _ => {
                if join_material.is_some() {
                    return Err(Error::InvalidKey);
                }
                (None, None)
            }
        };
        let mut builder = group
            .commit_builder()
            .propose_group_context_extensions(policy_extensions(&candidate)?)
            .map_err(|_| Error::Mls("propose policy extension"))?;
        if let Some(package) = add {
            builder = builder.propose_adds([package]);
        }
        if let Some(index) = remove {
            builder = builder.propose_removals([index]);
        }
        let bundle = builder
            .load_psks(provider.storage())
            .map_err(|_| Error::Mls("load pre-shared keys"))?
            .build(provider.rand(), provider.crypto(), &signer, |_| true)
            .map_err(|_| Error::Mls("build policy commit"))?
            .stage_commit(provider)
            .map_err(|_| Error::Mls("stage policy commit"))?;
        let commit = bundle
            .commit()
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)?;
        let welcome = bundle
            .to_welcome_msg()
            .map(|message| message.tls_serialize_detached())
            .transpose()
            .map_err(|_| Error::Serialization)?;
        let pending = PendingMutation {
            commit,
            policy: candidate,
            event,
            welcome,
        };
        self.pending = Some(pending.clone());
        Ok(pending)
    }

    pub fn propose_leave<I: SecureIdentity>(
        &mut self,
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
    ) -> Result<Vec<u8>, Error> {
        let actor = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        self.policy.can_leave(actor)?;
        let signer = PlatformMlsSigner(identity);
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        let own_binding =
            binding_from_credential(group.credential().map_err(|_| Error::InvalidKey)?)?;
        if own_binding.root_public_key() != actor {
            return Err(Error::InvalidSignature);
        }
        let own_index = group.own_leaf_index();
        let (proposal, _) = group
            .propose_remove_member(provider, &signer, own_index)
            .map_err(|_| Error::Mls("create self-remove proposal"))?;
        proposal
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)
    }

    pub fn stage_leave_candidate<I: SecureIdentity>(
        &mut self,
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        departing: [u8; 32],
        proposal: &[u8],
    ) -> Result<PendingMutation, Error> {
        if self.pending.is_some() {
            return Err(Error::Mls("candidate already pending"));
        }
        if proposal.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("MLS proposal bytes"));
        }
        let committer = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        let action = GroupAction::Leave {
            actor: departing,
            committer,
        };
        let signer = PlatformMlsSigner(identity);
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        if queue_self_remove(&mut group, provider, proposal)? != departing {
            return Err(Error::InvalidSignature);
        }
        let (candidate, event) = self.policy.apply(&action)?;
        let bundle = group
            .commit_builder()
            .propose_group_context_extensions(policy_extensions(&candidate)?)
            .map_err(|_| Error::Mls("propose leave policy extension"))?
            .load_psks(provider.storage())
            .map_err(|_| Error::Mls("load pre-shared keys"))?
            .build(provider.rand(), provider.crypto(), &signer, |_| true)
            .map_err(|_| Error::Mls("build leave commit"))?
            .stage_commit(provider)
            .map_err(|_| Error::Mls("stage leave commit"))?;
        let pending = PendingMutation {
            commit: bundle
                .commit()
                .tls_serialize_detached()
                .map_err(|_| Error::Serialization)?,
            policy: candidate,
            event,
            welcome: None,
        };
        self.pending = Some(pending.clone());
        Ok(pending)
    }

    pub fn receive_leave_proposal(
        &mut self,
        storage: &mut TransactionalOpenMlsStorage,
        proposal: &[u8],
    ) -> Result<[u8; 32], Error> {
        if proposal.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("MLS proposal bytes"));
        }
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        let departing = queue_self_remove(&mut group, provider, proposal)?;
        self.policy.can_leave(departing)?;
        Ok(departing)
    }

    pub fn merge_canonical(
        &mut self,
        storage: &mut TransactionalOpenMlsStorage,
        commit: &[u8],
    ) -> Result<PolicyEvent, Error> {
        if commit.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("MLS commit bytes"));
        }
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        if let Some(pending) = self.pending.take() {
            if pending.commit != commit {
                self.pending = Some(pending);
                return Err(Error::InvalidSignature);
            }
            group
                .merge_pending_commit(provider)
                .map_err(|_| Error::Mls("merge local canonical commit"))?;
            verify_group_policy(&group, &pending.policy)?;
            self.policy = pending.policy;
            self.epoch = group.epoch().as_u64();
            return Ok(pending.event);
        }

        let message =
            MlsMessageIn::tls_deserialize_exact(commit).map_err(|_| Error::Serialization)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| Error::Serialization)?;
        let processed = group
            .process_message(provider, protocol_message)
            .map_err(|_| Error::Mls("authenticate canonical commit"))?;
        let actor = binding_from_credential(processed.credential())?.root_public_key();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(Error::Mls("canonical message was not a commit"));
        };
        let candidate = policy_from_extensions(staged.group_context().extensions())?;
        let event = if let Some(departing) = authenticated_self_remove(&group, &staged, actor)? {
            self.policy.authenticate_action(
                &candidate,
                &GroupAction::Leave {
                    actor: departing,
                    committer: actor,
                },
            )?
        } else {
            self.policy.authenticate_candidate(&candidate, actor)?
        };
        validate_membership_proposals(&group, &staged, &event)?;
        group
            .merge_staged_commit(provider, *staged)
            .map_err(|_| Error::Mls("merge remote canonical commit"))?;
        verify_group_policy(&group, &candidate)?;
        self.policy = candidate;
        self.epoch = group.epoch().as_u64();
        Ok(event)
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn policy(&self) -> &PigeonGroupPolicy {
        &self.policy
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

fn policy_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(POLICY_EXTENSION_TYPE_ID)])
        .credentials(vec![CredentialType::Basic])
        .build()
}

fn policy_extensions(policy: &PigeonGroupPolicy) -> Result<Extensions<GroupContext>, Error> {
    Extensions::try_from(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(POLICY_EXTENSION_TYPE_ID)],
            &[],
            &[CredentialType::Basic],
        )),
        Extension::Unknown(POLICY_EXTENSION_TYPE_ID, UnknownExtension(policy.encode())),
    ])
    .map_err(|_| Error::Serialization)
}

fn policy_from_extensions(
    extensions: &Extensions<GroupContext>,
) -> Result<PigeonGroupPolicy, Error> {
    let extension = extensions
        .unknown(POLICY_EXTENSION_TYPE_ID)
        .ok_or(Error::InvalidSignature)?;
    PigeonGroupPolicy::decode(&extension.0).map_err(Error::from)
}

fn binding_from_credential(credential: &Credential) -> Result<MlsIdentityBinding, Error> {
    if credential.credential_type() != CredentialType::Basic {
        return Err(Error::InvalidKey);
    }
    MlsIdentityBinding::decode_credential(credential.serialized_content())
}

fn verify_staged_roster(staged: &StagedWelcome, policy: &PigeonGroupPolicy) -> Result<(), Error> {
    let mut roots = staged
        .members()
        .map(|member| {
            binding_from_credential(&member.credential).map(|binding| binding.root_public_key())
        })
        .collect::<Result<Vec<_>, _>>()?;
    roots.sort_unstable();
    if roots != policy.members() {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

fn verify_group_policy(group: &MlsGroup, policy: &PigeonGroupPolicy) -> Result<(), Error> {
    if policy_from_extensions(group.extensions())? != *policy {
        return Err(Error::InvalidSignature);
    }
    let mut roots = group
        .members()
        .map(|member| {
            binding_from_credential(&member.credential).map(|binding| binding.root_public_key())
        })
        .collect::<Result<Vec<_>, _>>()?;
    roots.sort_unstable();
    if roots != policy.members() {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

fn member_index(group: &MlsGroup, identity: [u8; 32]) -> Result<LeafNodeIndex, Error> {
    group
        .members()
        .find_map(|member| {
            binding_from_credential(&member.credential)
                .ok()
                .filter(|binding| binding.root_public_key() == identity)
                .map(|_| member.index)
        })
        .ok_or(Error::InvalidKey)
}

fn member_identity(group: &MlsGroup, index: LeafNodeIndex) -> Result<[u8; 32], Error> {
    group
        .members()
        .find(|member| member.index == index)
        .ok_or(Error::InvalidKey)
        .and_then(|member| binding_from_credential(&member.credential))
        .map(|binding| binding.root_public_key())
}

fn authenticated_self_remove(
    group: &MlsGroup,
    staged: &StagedCommit,
    committer: [u8; 32],
) -> Result<Option<[u8; 32]>, Error> {
    let mut removals = staged.remove_proposals();
    let Some(removal) = removals.next() else {
        return Ok(None);
    };
    if removals.next().is_some() {
        return Err(Error::InvalidSignature);
    }
    let removed = member_identity(group, removal.remove_proposal().removed())?;
    let Sender::Member(sender_index) = removal.sender() else {
        return Ok(None);
    };
    let proposer = member_identity(group, *sender_index)?;
    Ok((proposer == removed && proposer != committer).then_some(removed))
}

fn validate_membership_proposals(
    group: &MlsGroup,
    staged: &StagedCommit,
    event: &PolicyEvent,
) -> Result<(), Error> {
    let adds: Vec<_> = staged.add_proposals().collect();
    let removals: Vec<_> = staged.remove_proposals().collect();
    match event.kind {
        super::PolicyEventKind::MemberAdded => {
            let subject = event.subject.ok_or(Error::InvalidSignature)?;
            if adds.len() != 1 || !removals.is_empty() {
                return Err(Error::InvalidSignature);
            }
            let binding = binding_from_credential(
                adds[0]
                    .add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential(),
            )?;
            if binding.root_public_key() != subject {
                return Err(Error::InvalidSignature);
            }
        }
        super::PolicyEventKind::MemberRemoved | super::PolicyEventKind::MemberLeft => {
            let subject = event.subject.ok_or(Error::InvalidSignature)?;
            if !adds.is_empty()
                || removals.len() != 1
                || member_identity(group, removals[0].remove_proposal().removed())? != subject
            {
                return Err(Error::InvalidSignature);
            }
        }
        _ if !adds.is_empty() || !removals.is_empty() => return Err(Error::InvalidSignature),
        _ => {}
    }
    Ok(())
}

fn queue_self_remove(
    group: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
    proposal: &[u8],
) -> Result<[u8; 32], Error> {
    if group.has_pending_proposals() {
        return Err(Error::Mls("unrelated proposal already pending"));
    }
    let message =
        MlsMessageIn::tls_deserialize_exact(proposal).map_err(|_| Error::Serialization)?;
    let protocol_message = message
        .try_into_protocol_message()
        .map_err(|_| Error::Serialization)?;
    let processed = group
        .process_message(provider, protocol_message)
        .map_err(|_| Error::Mls("authenticate self-remove proposal"))?;
    let proposer = binding_from_credential(processed.credential())?.root_public_key();
    let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
        return Err(Error::Mls("leave input was not a proposal"));
    };
    let Proposal::Remove(remove) = queued.proposal() else {
        return Err(Error::Mls("leave input was not a remove proposal"));
    };
    if remove.removed() != member_index(group, proposer)?
        || !matches!(queued.sender(), Sender::Member(index) if *index == remove.removed())
    {
        return Err(Error::InvalidSignature);
    }
    group
        .store_pending_proposal(provider.storage(), *queued)
        .map_err(|_| Error::Mls("store self-remove proposal"))?;
    Ok(proposer)
}

fn load_group(provider: &impl OpenMlsProvider, group_id: GroupId) -> Result<MlsGroup, Error> {
    MlsGroup::load(
        provider.storage(),
        &openmls::prelude::GroupId::from_slice(group_id.as_bytes()),
    )
    .map_err(|_| Error::Mls("load group"))?
    .ok_or(Error::Mls("group not found"))
}

fn action_actor(action: &GroupAction) -> [u8; 32] {
    match action {
        GroupAction::Add { actor, .. }
        | GroupAction::Remove { actor, .. }
        | GroupAction::Leave { actor, .. }
        | GroupAction::Promote { actor, .. }
        | GroupAction::Demote { actor, .. }
        | GroupAction::Rename { actor, .. }
        | GroupAction::SetMesh { actor, .. }
        | GroupAction::SetRelay { actor, .. }
        | GroupAction::Dissolve { actor } => *actor,
    }
}
