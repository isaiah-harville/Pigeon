use prost::Message;

use super::PigeonClient;
use crate::Error;
use crate::client::{AppEvent, ClientOutput, OutboundItem};
use crate::group::{
    CoordinatorChain, CoordinatorChainError, CoordinatorReceipt, GroupAction, GroupEngine,
    GroupMutationCandidate, GroupRelayControl, PigeonGroupPolicy, PolicyEvent, PolicyEventKind,
};
use crate::identity::{GroupJoinMaterial, GroupJoinRequest, IdentityPurpose, SecureIdentity};
use crate::storage::{StateStore, TransactionalOpenMlsStorage};
use crate::wire::{PROTOCOL_VERSION, proto};

const GROUP_SECURITY_COORDINATOR_FORK_CODE: u32 = 1;

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
        let group_index = candidate
            .groups
            .iter()
            .position(|stored| {
                PigeonGroupPolicy::decode(&stored.policy)
                    .is_ok_and(|policy| policy.coordination_id() == receipt.coordination_id)
            })
            .ok_or(Error::InvalidKey)?;
        let stored = candidate.groups[group_index].clone();
        let prior = PigeonGroupPolicy::decode(&stored.policy)?;
        let mut chain = CoordinatorChain::decode(
            &stored.coordinator_chain,
            prior.coordination_id(),
            prior.coordinator_public_key(),
        )
        .map_err(|_| Error::InvalidSignature)?;
        match chain.accept(&receipt, &opaque_candidate) {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(CoordinatorChainError::Fork) => {
                candidate.groups[group_index].coordinator_chain = chain.encode();
                output.events.push(AppEvent {
                    inner: proto::AppEvent {
                        version: PROTOCOL_VERSION,
                        event_id: format!("{command_id}:coordinator-fork"),
                        body: Some(proto::app_event::Body::GroupSecurityWarning(
                            proto::GroupSecurityWarning {
                                group_id: stored.group_id,
                                code: GROUP_SECURITY_COORDINATOR_FORK_CODE,
                                evidence_id: receipt.receipt_hash().to_vec(),
                                epoch: stored.epoch,
                            },
                        )),
                    },
                });
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
            GroupEngine::restore_pending(
                &mls_storage,
                prior.clone(),
                stored.epoch,
                pending.commit.clone(),
                next_policy,
                event,
            )?
        } else {
            GroupEngine::restore(&mls_storage, prior.clone(), stored.epoch)?
        };
        let event = engine.merge_canonical_candidate(&mut mls_storage, &mutation)?;
        let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let relay_control = if prior.is_admin(local_identity) {
            GroupRelayControl::for_transition(&prior, engine.policy(), &event)?
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
        output.events.push(AppEvent {
            inner: proto::AppEvent {
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
            },
        });
        if let Some(control) = relay_control {
            output.outbound.push(OutboundItem {
                inner: proto::OutboundItem {
                    item_id: format!("{command_id}:relay-control"),
                    kind: proto::OutboundKind::GroupRelayControl as i32,
                    relay_url: prior.relay_url().to_owned(),
                    destination: prior.coordination_id().to_vec(),
                    payload: control.encode(),
                },
            });
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
            },
        });
        Ok(())
    }

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
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: format!("{command_id}:leave-proposal"),
                kind: proto::OutboundKind::GroupLeaveProposal as i32,
                relay_url: stored.relay_url,
                destination: engine.policy().coordination_id().to_vec(),
                payload: proto::GroupLeaveProposal {
                    version: PROTOCOL_VERSION,
                    group_id: change.group_id.clone(),
                    proposal,
                    departing_identity: departing.to_vec(),
                }
                .encode_to_vec(),
            },
        });
        Ok(())
    }

    pub(super) fn stage_apply_group_addition_material(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        material: &GroupJoinMaterial,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<bool, Error> {
        let Some(addition_index) = candidate
            .pending_group_additions
            .iter()
            .position(|addition| addition.request_id == inbound.request_id)
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
            },
        });
        Ok(())
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
