use prost::Message;

use super::PigeonClient;
use crate::Error;
use crate::client::{AppEvent, ClientOutput, OutboundItem};
use crate::group::{
    CoordinatorChain, CoordinatorReceipt, GroupAction, GroupEngine, GroupRelayControl,
    PigeonGroupPolicy, PolicyEvent, PolicyEventKind,
};
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::storage::{StateStore, TransactionalOpenMlsStorage};
use crate::wire::{PROTOCOL_VERSION, proto};

impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_apply_group_coordinator(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let (receipt, commit) = CoordinatorReceipt::decode_candidate(&inbound.payload)
            .map_err(|_| Error::InvalidSignature)?;
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
        if !chain
            .accept(&receipt, &commit)
            .map_err(|_| Error::InvalidSignature)?
        {
            return Ok(());
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
            .position(|pending| pending.group_id == stored.group_id)
            .ok_or(Error::InvalidSignature)?;
        let pending = candidate.pending_group_mutations[pending_index].clone();
        if pending.base_epoch != stored.epoch || pending.commit != commit {
            return Err(Error::InvalidSignature);
        }
        let next_policy = PigeonGroupPolicy::decode(&pending.next_policy)?;
        let event = decode_event(&pending, next_policy.revision())?;
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore_pending(
            &mls_storage,
            prior.clone(),
            stored.epoch,
            pending.commit,
            next_policy,
            event,
        )?;
        let event = engine.merge_canonical(&mut mls_storage, &commit)?;
        let relay_control = GroupRelayControl::for_transition(&prior, engine.policy(), &event)?;
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        let mut updated = super::checkpoint::stored_group(&engine);
        updated.coordinator_chain = chain.encode();
        candidate.groups[group_index] = updated;
        candidate.pending_group_mutations.remove(pending_index);
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
        Ok(())
    }

    pub(super) fn stage_change_group_policy(
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
        let actor = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let action = action_from_change(change, actor)?;
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
        let pending = engine.stage_candidate(&self.identity, &mut mls_storage, action, None)?;
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
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
                    candidate: pending.commit().to_vec(),
                }
                .encode_to_vec(),
            },
        });
        Ok(())
    }
}

fn action_from_change(
    change: &proto::ChangeGroupPolicy,
    actor: [u8; 32],
) -> Result<GroupAction, Error> {
    let kind =
        proto::GroupPolicyChangeKind::try_from(change.kind).map_err(|_| Error::MalformedBundle)?;
    let subject = || {
        change
            .subject_identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)
    };
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
