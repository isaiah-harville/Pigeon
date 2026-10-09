impl GroupEngine {
    pub fn stage_recovery<I: SecureIdentity>(
        &mut self,
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        certificate: &RecoveryCertificate,
        receipt_head: [u8; 32],
    ) -> Result<PendingMutation, Error> {
        if self.pending.is_some() {
            return Err(Error::Mls("candidate already pending"));
        }
        certificate
            .verify(&self.policy, self.epoch, receipt_head)
            .map_err(|_| Error::InvalidSignature)?;
        let actor = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        let (candidate, event) = self.policy.recovered_policy(actor, certificate)?;
        let signer = PlatformMlsSigner(identity);
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        let bundle = group
            .commit_builder()
            .propose_group_context_extensions(policy_extensions(&candidate)?)
            .map_err(|_| Error::Mls("propose recovery policy extension"))?
            .load_psks(provider.storage())
            .map_err(|_| Error::Mls("load pre-shared keys"))?
            .build(provider.rand(), provider.crypto(), &signer, |_| true)
            .map_err(|_| Error::Mls("build recovery commit"))?
            .stage_commit(provider)
            .map_err(|_| Error::Mls("stage recovery commit"))?;
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
        if group.has_pending_proposals() {
            return Err(Error::Mls("unrelated proposal already pending"));
        }
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
        let candidate = GroupMutationCandidate::new(Vec::new(), commit.to_vec())?;
        self.merge_canonical_candidate(storage, &candidate)
    }

    pub fn merge_canonical_candidate(
        &mut self,
        storage: &mut TransactionalOpenMlsStorage,
        candidate: &GroupMutationCandidate,
    ) -> Result<PolicyEvent, Error> {
        self.merge_candidate(storage, candidate, None)
    }

    pub fn merge_recovery_candidate(
        &mut self,
        storage: &mut TransactionalOpenMlsStorage,
        candidate: &GroupMutationCandidate,
        certificate: &RecoveryCertificate,
        receipt_head: [u8; 32],
    ) -> Result<PolicyEvent, Error> {
        self.merge_candidate(storage, candidate, Some((certificate, receipt_head)))
    }

    fn merge_candidate(
        &mut self,
        storage: &mut TransactionalOpenMlsStorage,
        candidate: &GroupMutationCandidate,
        recovery: Option<(&RecoveryCertificate, [u8; 32])>,
    ) -> Result<PolicyEvent, Error> {
        match (candidate.recovery_certificate(), recovery) {
            (Some(encoded), Some((certificate, receipt_head)))
                if encoded == certificate.encode().as_slice() =>
            {
                certificate
                    .verify(&self.policy, self.epoch, receipt_head)
                    .map_err(|_| Error::InvalidSignature)?;
            }
            (None, None) => {}
            _ => return Err(Error::InvalidSignature),
        }
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        let mut discarded_local_commit = false;
        if let Some(pending) = self.pending.take() {
            if pending.commit == candidate.commit() {
                group
                    .merge_pending_commit(provider)
                    .map_err(|_| Error::Mls("merge local canonical commit"))?;
                verify_group_policy(&group, &pending.policy)?;
                self.policy = pending.policy;
                self.epoch = group.epoch().as_u64();
                return Ok(pending.event);
            }
            group
                .clear_pending_commit(provider.storage())
                .map_err(|_| Error::Mls("discard non-canonical local commit"))?;
            discarded_local_commit = true;
        }

        if discarded_local_commit || !group.has_pending_proposals() {
            group
                .clear_pending_proposals(provider.storage())
                .map_err(|_| Error::Mls("clear non-canonical proposals"))?;
            for proposal in candidate.proposals() {
                queue_self_remove(&mut group, provider, proposal)?;
            }
        }

        let message = MlsMessageIn::tls_deserialize_exact(candidate.commit())
            .map_err(|_| Error::Serialization)?;
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
        let event = if let Some((certificate, _)) = recovery {
            self.policy.recover(&candidate, actor, certificate)?
        } else if let Some(departing) = authenticated_self_remove(&group, &staged, actor)? {
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
