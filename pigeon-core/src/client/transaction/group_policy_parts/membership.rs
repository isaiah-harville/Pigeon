impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_apply_group_leave_proposal(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let leave = proto::GroupLeaveProposal::decode(inbound.payload.as_slice())
            .map_err(|_| Error::MalformedBundle)?;
        if leave.version != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group leave proposal",
                version: leave.version,
            });
        }
        if leave.group_id.len() != 32
            || leave.departing_identity.len() != 32
            || leave.proposal.is_empty()
            || leave.proposal.len() > crate::MAX_MLS_OBJECT_BYTES
        {
            return Err(Error::MalformedBundle);
        }
        if candidate
            .pending_group_mutations
            .iter()
            .any(|pending| pending.group_id == leave.group_id)
        {
            return Err(Error::Mls("group mutation already pending"));
        }
        let stored = candidate
            .groups
            .iter()
            .find(|group| group.group_id == leave.group_id)
            .cloned()
            .ok_or(Error::InvalidKey)?;
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let committer = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        if !policy.is_admin(committer) {
            return Ok(());
        }
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
        let departing = leave
            .departing_identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let pending = engine.stage_leave_candidate(
            &self.identity,
            &mut mls_storage,
            departing,
            &leave.proposal,
        )?;
        let coordinator_candidate =
            GroupMutationCandidate::new(vec![leave.proposal], pending.commit().to_vec())?.encode();
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        candidate
            .pending_group_mutations
            .push(proto::PendingGroupMutation {
                group_id: leave.group_id,
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
        output.outbound.push(coordinator_submission(
            command_id,
            &stored,
            engine.policy().coordination_id(),
            coordinator_candidate,
        ));
        Ok(())
    }

    fn stage_propose_group_leave(
        &self,
        command_id: &str,
        change: &proto::ChangeGroupPolicy,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        if candidate
            .pending_group_leaves
            .iter()
            .any(|pending| pending.group_id == change.group_id)
        {
            return Err(Error::Mls("group leave already pending"));
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
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
        let proposal = engine.propose_leave(&self.identity, &mut mls_storage)?;
        let departing = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let leave = proto::GroupLeaveProposal {
            version: PROTOCOL_VERSION,
            group_id: change.group_id.clone(),
            proposal,
            departing_identity: departing.to_vec(),
        }
        .encode_to_vec();
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        for (index, admin) in engine.policy().admins().iter().enumerate() {
            if *admin == departing {
                continue;
            }
            output.outbound.push(OutboundItem {
                inner: proto::OutboundItem {
                    item_id: format!("{command_id}:leave-proposal:{index}"),
                    kind: proto::OutboundKind::GroupLeaveProposal as i32,
                    relay_url: stored.relay_url.clone(),
                    destination: admin.to_vec(),
                    payload: leave.clone(),
                    local_only: false,
                },
            });
        }
        if output.outbound.is_empty() {
            return Err(Error::GroupPolicy(crate::group::PolicyError::InvalidRoster));
        }
        candidate
            .pending_group_leaves
            .push(proto::PendingGroupLeave {
                group_id: change.group_id.clone(),
            });
        Ok(())
    }

    pub(super) fn stage_apply_group_addition_material(
        &self,
        command_id: &str,
        _inbound: &proto::ApplyInbound,
        material: &GroupJoinMaterial,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<bool, Error> {
        let Some(addition_index) = candidate
            .pending_group_additions
            .iter()
            .position(|addition| {
                addition.group_id.as_slice() == material.member_keys().group_id().as_bytes()
                    && addition.member_identity.as_slice() == material.member_identity()
            })
        else {
            return Ok(false);
        };
        let addition = candidate.pending_group_additions[addition_index].clone();
        if candidate
            .pending_group_mutations
            .iter()
            .any(|pending| pending.group_id == addition.group_id)
        {
            return Err(Error::Mls("group mutation already pending"));
        }
        let stored = candidate
            .groups
            .iter()
            .find(|group| group.group_id == addition.group_id)
            .cloned()
            .ok_or(Error::InvalidKey)?;
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let actor = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        material.verify_for_requester(
            actor,
            policy.owner(),
            policy.group_id(),
            policy.coordination_id(),
        )?;
        if material.member_identity().as_slice() != addition.member_identity {
            return Err(Error::InvalidSignature);
        }
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
        let pending = engine.stage_candidate(
            &self.identity,
            &mut mls_storage,
            GroupAction::Add {
                actor,
                member_keys: Box::new(material.member_keys()),
            },
            Some(material.clone()),
        )?;
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        if candidate.consumed_key_package_hashes.len() >= crate::MAX_PENDING_OUTBOUND_ENTRIES {
            candidate.consumed_key_package_hashes.remove(0);
        }
        candidate
            .consumed_key_package_hashes
            .push(material.package_hash().to_vec());
        let coordinator_candidate =
            GroupMutationCandidate::new(Vec::new(), pending.commit().to_vec())?.encode();
        candidate
            .pending_group_mutations
            .push(proto::PendingGroupMutation {
                group_id: addition.group_id.clone(),
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
                welcome: pending.welcome().ok_or(Error::Serialization)?.to_vec(),
                welcome_destination: addition.member_identity,
                coordinator_candidate: coordinator_candidate.clone(),
            });
        candidate.pending_group_additions.remove(addition_index);
        output.outbound.push(coordinator_submission(
            command_id,
            &stored,
            engine.policy().coordination_id(),
            coordinator_candidate,
        ));
        Ok(true)
    }

    fn stage_invite_group_member(
        &self,
        command_id: &str,
        change: &proto::ChangeGroupPolicy,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        if candidate
            .pending_group_mutations
            .iter()
            .any(|pending| pending.group_id == change.group_id)
            || candidate
                .pending_group_additions
                .iter()
                .any(|addition| addition.group_id == change.group_id)
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
        let subject = decode_subject(&change.subject_identity)?;
        policy.can_invite(actor, subject)?;
        let request = GroupJoinRequest::create_for_owner(
            &self.identity,
            policy.owner(),
            policy.group_id(),
            policy.coordination_id(),
            policy.relay_url(),
        )?;
        let request_id = format!("{command_id}:join");
        candidate
            .pending_group_additions
            .push(proto::PendingGroupAddition {
                request_id: request_id.clone(),
                group_id: change.group_id.clone(),
                member_identity: subject.to_vec(),
            });
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: request_id,
                kind: proto::OutboundKind::GroupJoinRequest as i32,
                relay_url: stored.relay_url,
                destination: subject.to_vec(),
                payload: request.encode(),
                local_only: false,
            },
        });
        Ok(())
    }
}


fn coordinator_fork_event(
    command_id: &str,
    stored: &proto::StoredGroup,
    receipt: &CoordinatorReceipt,
) -> AppEvent {
    AppEvent {
        inner: proto::AppEvent {
            version: PROTOCOL_VERSION,
            event_id: format!("{command_id}:coordinator-fork"),
            body: Some(proto::app_event::Body::GroupSecurityWarning(
                proto::GroupSecurityWarning {
                    group_id: stored.group_id.clone(),
                    code: GROUP_SECURITY_COORDINATOR_FORK_CODE,
                    evidence_id: receipt.receipt_hash().to_vec(),
                    epoch: stored.epoch,
                },
            )),
        },
    }
}

fn coordinator_submission(
    command_id: &str,
    stored: &proto::StoredGroup,
    coordination_id: [u8; 32],
    candidate: Vec<u8>,
) -> OutboundItem {
    OutboundItem {
        inner: proto::OutboundItem {
            item_id: format!("{command_id}:coordinate"),
            kind: proto::OutboundKind::GroupCoordinator as i32,
            relay_url: stored.relay_url.clone(),
            destination: coordination_id.to_vec(),
            payload: proto::GroupCoordinatorSubmission {
                version: PROTOCOL_VERSION,
                claimed_base_epoch: stored.epoch,
                candidate,
            }
            .encode_to_vec(),
            local_only: false,
        },
    }
}

fn decode_subject(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::InvalidKey)
}

fn action_from_change(
    change: &proto::ChangeGroupPolicy,
    actor: [u8; 32],
) -> Result<GroupAction, Error> {
    let kind =
        proto::GroupPolicyChangeKind::try_from(change.kind).map_err(|_| Error::MalformedBundle)?;
    let subject = || decode_subject(&change.subject_identity);
    match kind {
        proto::GroupPolicyChangeKind::MemberRemoved => Ok(GroupAction::Remove {
            actor,
            subject: subject()?,
        }),
        proto::GroupPolicyChangeKind::AdminPromoted => Ok(GroupAction::Promote {
            actor,
            subject: subject()?,
        }),
        proto::GroupPolicyChangeKind::AdminDemoted => Ok(GroupAction::Demote {
            actor,
            subject: subject()?,
        }),
        proto::GroupPolicyChangeKind::NameChanged => Ok(GroupAction::Rename {
            actor,
            name: change.string_value.clone(),
        }),
        proto::GroupPolicyChangeKind::MeshChanged => Ok(GroupAction::SetMesh {
            actor,
            enabled: change.bool_value,
        }),
        proto::GroupPolicyChangeKind::RelayChanged => Ok(GroupAction::SetRelay {
            actor,
            relay_url: change.string_value.clone(),
        }),
        proto::GroupPolicyChangeKind::Dissolved => Ok(GroupAction::Dissolve { actor }),
        _ => Err(Error::MalformedBundle),
    }
}

fn event_kind(kind: PolicyEventKind) -> proto::GroupPolicyChangeKind {
    match kind {
        PolicyEventKind::MemberAdded => proto::GroupPolicyChangeKind::MemberAdded,
        PolicyEventKind::MemberRemoved => proto::GroupPolicyChangeKind::MemberRemoved,
        PolicyEventKind::MemberLeft => proto::GroupPolicyChangeKind::MemberLeft,
        PolicyEventKind::AdminPromoted => proto::GroupPolicyChangeKind::AdminPromoted,
        PolicyEventKind::AdminDemoted => proto::GroupPolicyChangeKind::AdminDemoted,
        PolicyEventKind::NameChanged => proto::GroupPolicyChangeKind::NameChanged,
        PolicyEventKind::MeshChanged => proto::GroupPolicyChangeKind::MeshChanged,
        PolicyEventKind::RelayChanged => proto::GroupPolicyChangeKind::RelayChanged,
        PolicyEventKind::Dissolved => proto::GroupPolicyChangeKind::Dissolved,
    }
}

fn decode_event(
    pending: &proto::PendingGroupMutation,
    revision: u64,
) -> Result<PolicyEvent, Error> {
    let kind = match proto::GroupPolicyChangeKind::try_from(pending.event_kind)
        .map_err(|_| Error::Serialization)?
    {
        proto::GroupPolicyChangeKind::MemberAdded => PolicyEventKind::MemberAdded,
        proto::GroupPolicyChangeKind::MemberRemoved => PolicyEventKind::MemberRemoved,
        proto::GroupPolicyChangeKind::MemberLeft => PolicyEventKind::MemberLeft,
        proto::GroupPolicyChangeKind::AdminPromoted => PolicyEventKind::AdminPromoted,
        proto::GroupPolicyChangeKind::AdminDemoted => PolicyEventKind::AdminDemoted,
        proto::GroupPolicyChangeKind::NameChanged => PolicyEventKind::NameChanged,
        proto::GroupPolicyChangeKind::MeshChanged => PolicyEventKind::MeshChanged,
        proto::GroupPolicyChangeKind::RelayChanged => PolicyEventKind::RelayChanged,
        proto::GroupPolicyChangeKind::Dissolved => PolicyEventKind::Dissolved,
        proto::GroupPolicyChangeKind::Unspecified => return Err(Error::Serialization),
    };
    Ok(PolicyEvent {
        kind,
        actor: pending
            .actor_identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
        subject: if pending.subject_identity.is_empty() {
            None
        } else {
            Some(
                pending
                    .subject_identity
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
            )
        },
        revision,
    })
}
