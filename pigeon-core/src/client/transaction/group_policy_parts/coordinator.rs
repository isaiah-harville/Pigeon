impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_apply_group_coordinator(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let (receipt, opaque_candidate) = CoordinatorReceipt::decode_candidate(&inbound.payload)
            .map_err(|_| Error::InvalidSignature)?;
        let mutation = GroupMutationCandidate::decode(&opaque_candidate)?;
        let recovery = mutation
            .recovery_certificate()
            .map(RecoveryCertificate::decode)
            .transpose()
            .map_err(|_| Error::InvalidSignature)?;
        let group_index = candidate
            .groups
            .iter()
            .position(|stored| {
                recovery.as_ref().map_or_else(
                    || {
                        PigeonGroupPolicy::decode(&stored.policy)
                            .is_ok_and(|policy| policy.coordination_id() == receipt.coordination_id)
                    },
                    |certificate| {
                        stored.group_id.as_slice() == certificate.proposal().group_id().as_slice()
                    },
                )
            })
            .ok_or(Error::InvalidKey)?;
        let stored = candidate.groups[group_index].clone();
        let prior = PigeonGroupPolicy::decode(&stored.policy)?;
        let prior_chain = CoordinatorChain::decode(
            &stored.coordinator_chain,
            prior.coordination_id(),
            prior.coordinator_public_key(),
        )
        .map_err(|_| Error::InvalidSignature)?;
        if recovery.is_some() && receipt.coordination_id == prior.coordination_id() {
            let mut replay_chain = prior_chain.clone();
            match replay_chain.accept(&receipt, &opaque_candidate) {
                Ok(false) => return Ok(()),
                Err(CoordinatorChainError::Fork) => {
                    candidate.groups[group_index].coordinator_chain = replay_chain.encode();
                    output
                        .events
                        .push(coordinator_fork_event(command_id, &stored, &receipt));
                    return Ok(());
                }
                Ok(true) | Err(_) => return Err(Error::InvalidSignature),
            }
        }
        let recovery_receipt_head = recovery.as_ref().map(|_| prior_chain.receipt_head());
        let mut chain = if let Some(certificate) = &recovery {
            certificate
                .verify(&prior, stored.epoch, prior_chain.receipt_head())
                .map_err(|_| Error::InvalidSignature)?;
            let replacement = certificate.proposal().replacement();
            if receipt.coordination_id != replacement.coordination_id {
                return Err(Error::InvalidSignature);
            }
            CoordinatorChain::new(replacement.coordination_id, replacement.public_key)
        } else {
            prior_chain
        };
        if recovery.is_some() && receipt.claimed_base_epoch != stored.epoch {
            return Err(Error::InvalidSignature);
        }
        match chain.accept(&receipt, &opaque_candidate) {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(CoordinatorChainError::Fork) => {
                candidate.groups[group_index].coordinator_chain = chain.encode();
                output
                    .events
                    .push(coordinator_fork_event(command_id, &stored, &receipt));
                return Ok(());
            }
            Err(_) => return Err(Error::InvalidSignature),
        }
        if receipt.claimed_base_epoch < stored.epoch {
            candidate.groups[group_index].coordinator_chain = chain.encode();
            return Ok(());
        }
        if receipt.claimed_base_epoch != stored.epoch {
            return Err(Error::InvalidSignature);
        }
        let pending_index = candidate
            .pending_group_mutations
            .iter()
            .position(|pending| pending.group_id == stored.group_id);
        let pending = pending_index.map(|index| candidate.pending_group_mutations[index].clone());
        if pending
            .as_ref()
            .is_some_and(|pending| pending.base_epoch != stored.epoch)
        {
            return Err(Error::InvalidSignature);
        }
        let canonical_is_local = pending.as_ref().is_some_and(|pending| {
            pending.coordinator_candidate == opaque_candidate && pending.commit == mutation.commit()
        });
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = if let Some(pending) = &pending {
            let next_policy = PigeonGroupPolicy::decode(&pending.next_policy)?;
            let event = decode_event(pending, next_policy.revision())?;
            if let Some(certificate) = &recovery {
                GroupEngine::restore_recovery_pending(
                    &mls_storage,
                    prior.clone(),
                    stored.epoch,
                    pending.commit.clone(),
                    next_policy,
                    event,
                    certificate,
                )?
            } else {
                GroupEngine::restore_pending(
                    &mls_storage,
                    prior.clone(),
                    stored.epoch,
                    pending.commit.clone(),
                    next_policy,
                    event,
                )?
            }
        } else {
            GroupEngine::restore(&mls_storage, prior.clone(), stored.epoch)?
        };
        let recovery_broadcast = if recovery.is_some() && canonical_is_local {
            Some(engine.encrypt_application(
                &self.identity,
                &mut mls_storage,
                GroupApplication::recovery_control(
                    RecoveryControlKind::Candidate,
                    None,
                    inbound.payload.clone(),
                ),
            )?)
        } else {
            None
        };
        let event =
            if let (Some(certificate), Some(receipt_head)) = (&recovery, recovery_receipt_head) {
                engine.merge_recovery_candidate(
                    &mut mls_storage,
                    &mutation,
                    certificate,
                    receipt_head,
                )?
            } else {
                engine.merge_canonical_candidate(&mut mls_storage, &mutation)?
            };
        let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        if event.kind == PolicyEventKind::MemberLeft && event.subject == Some(local_identity) {
            candidate
                .pending_group_leaves
                .retain(|pending| pending.group_id != stored.group_id);
        }
        let relay_control = if recovery.is_none() && prior.is_admin(local_identity) {
            GroupRelayControl::for_transition(
                &prior,
                engine.policy(),
                stored.epoch,
                engine.epoch(),
                &event,
            )?
        } else {
            None
        };
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        let mut updated = super::checkpoint::stored_group(&engine);
        updated.coordinator_chain = chain.encode();
        candidate.groups[group_index] = updated;
        if let Some(index) = pending_index {
            candidate.pending_group_mutations.remove(index);
        }
        let mut retained_recoveries = Vec::with_capacity(candidate.pending_group_recoveries.len());
        for pending_recovery in candidate.pending_group_recoveries.drain(..) {
            let proposal = RecoveryProposal::decode(&pending_recovery.proposal)
                .map_err(|_| Error::InvalidSignature)?;
            if proposal.group_id() != *prior.group_id().as_bytes() {
                retained_recoveries.push(pending_recovery);
            }
        }
        candidate.pending_group_recoveries = retained_recoveries;
        if let Some(ciphertext) = recovery_broadcast {
            output.outbound.push(OutboundItem {
                inner: proto::OutboundItem {
                    item_id: format!("{command_id}:recovery-candidate"),
                    kind: proto::OutboundKind::GroupMessage as i32,
                    relay_url: stored.relay_url.clone(),
                    destination: prior.coordination_id().to_vec(),
                    payload: ciphertext.encode(),
                    local_only: false,
                },
            });
        }
        let app_event = proto::AppEvent {
            version: PROTOCOL_VERSION,
            event_id: format!("{command_id}:policy"),
            body: Some(proto::app_event::Body::GroupPolicyChanged(
                proto::GroupPolicyChanged {
                    kind: event_kind(event.kind) as i32,
                    group_id: engine.group_id().as_bytes().to_vec(),
                    actor_identity: event.actor.to_vec(),
                    subject_identity: event
                        .subject
                        .map(|subject| subject.to_vec())
                        .unwrap_or_default(),
                    epoch: engine.epoch(),
                    policy_revision: event.revision,
                    name: engine.policy().name().to_owned(),
                    mesh_enabled: engine.policy().mesh_enabled(),
                    relay_url: engine.policy().relay_url().to_owned(),
                },
            )),
        };
        if let Some(control) = relay_control {
            let item_id = format!("{command_id}:relay-control");
            let active_public_key = prior
                .member_capability_key(local_identity)
                .ok_or(Error::InvalidKey)?;
            candidate.deferred_events.push(proto::DeferredAppEvent {
                outbound_item_id: item_id.clone(),
                group_id: engine.group_id().as_bytes().to_vec(),
                active_capability_id: relay_capability_id(
                    *engine.group_id().as_bytes(),
                    prior.coordination_id(),
                    stored.epoch,
                    prior.revision(),
                    prior.roster_hash(),
                    active_public_key,
                )
                .to_vec(),
                event: Some(app_event),
                release_capability_id: Vec::new(),
            });
            output.outbound.push(OutboundItem {
                inner: proto::OutboundItem {
                    item_id,
                    kind: proto::OutboundKind::GroupRelayControl as i32,
                    relay_url: prior.relay_url().to_owned(),
                    destination: prior.coordination_id().to_vec(),
                    payload: control.encode(),
                    local_only: false,
                },
            });
        } else if engine.policy().members().contains(&local_identity) {
            let capability_public_key = engine
                .policy()
                .member_capability_key(local_identity)
                .ok_or(Error::InvalidKey)?;
            candidate.deferred_events.push(proto::DeferredAppEvent {
                outbound_item_id: String::new(),
                group_id: engine.group_id().as_bytes().to_vec(),
                active_capability_id: Vec::new(),
                event: Some(app_event),
                release_capability_id: relay_capability_id(
                    *engine.group_id().as_bytes(),
                    engine.policy().coordination_id(),
                    engine.epoch(),
                    engine.policy().revision(),
                    engine.policy().roster_hash(),
                    capability_public_key,
                )
                .to_vec(),
            });
        } else {
            output.events.push(AppEvent { inner: app_event });
        }
        if canonical_is_local
            && pending
                .as_ref()
                .is_some_and(|pending| !pending.welcome.is_empty())
        {
            let pending = pending.as_ref().ok_or(Error::Serialization)?;
            output.outbound.push(OutboundItem {
                inner: proto::OutboundItem {
                    item_id: format!("{command_id}:welcome"),
                    kind: proto::OutboundKind::GroupWelcome as i32,
                    relay_url: prior.relay_url().to_owned(),
                    destination: pending.welcome_destination.clone(),
                    payload: pending.welcome.clone(),
                    local_only: false,
                },
            });
        }
        Ok(())
    }

    pub(super) fn stage_change_group_policy(
        &self,
        command_id: &str,
        change: &proto::ChangeGroupPolicy,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let kind = proto::GroupPolicyChangeKind::try_from(change.kind)
            .map_err(|_| Error::MalformedBundle)?;
        if kind == proto::GroupPolicyChangeKind::MemberAdded {
            return self.stage_invite_group_member(command_id, change, candidate, output);
        }
        if kind == proto::GroupPolicyChangeKind::MemberLeft {
            return self.stage_propose_group_leave(command_id, change, candidate, output);
        }
        if candidate
            .pending_group_mutations
            .iter()
            .any(|pending| pending.group_id == change.group_id)
        {
            return Err(Error::Mls("group mutation already pending"));
        }
        let stored = candidate
            .groups
            .iter()
            .find(|group| group.group_id == change.group_id)
            .cloned()
            .ok_or(Error::InvalidKey)?;
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let actor = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let action = action_from_change(change, actor)?;
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
        let pending = engine.stage_candidate(&self.identity, &mut mls_storage, action, None)?;
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        let coordinator_candidate =
            GroupMutationCandidate::new(Vec::new(), pending.commit().to_vec())?.encode();
        candidate
            .pending_group_mutations
            .push(proto::PendingGroupMutation {
                group_id: change.group_id.clone(),
                base_epoch: stored.epoch,
                commit: pending.commit().to_vec(),
                next_policy: pending.next_policy().encode(),
                event_kind: event_kind(pending.event().kind) as i32,
                actor_identity: pending.event().actor.to_vec(),
                subject_identity: pending
                    .event()
                    .subject
                    .map(|subject| subject.to_vec())
                    .unwrap_or_default(),
                welcome: Vec::new(),
                welcome_destination: Vec::new(),
                coordinator_candidate: coordinator_candidate.clone(),
            });
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: format!("{command_id}:coordinate"),
                kind: proto::OutboundKind::GroupCoordinator as i32,
                relay_url: stored.relay_url,
                destination: engine.policy().coordination_id().to_vec(),
                payload: proto::GroupCoordinatorSubmission {
                    version: PROTOCOL_VERSION,
                    claimed_base_epoch: stored.epoch,
                    candidate: coordinator_candidate,
                }
                .encode_to_vec(),
                local_only: false,
            },
        });
        Ok(())
    }

}
