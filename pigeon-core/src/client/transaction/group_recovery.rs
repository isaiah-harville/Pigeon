use prost::Message;

use super::PigeonClient;
use crate::Error;
use crate::client::{ClientOutput, OutboundItem};
use crate::group::{
    CoordinatorBinding, CoordinatorChain, GroupApplication, GroupEngine, GroupId,
    GroupMutationCandidate, GroupRelayRegistration, PigeonGroupPolicy, RecoveryCertificate,
    RecoveryControlKind, RecoveryEndorsement, RecoveryError, RecoveryProposal,
};
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::storage::{StateStore, TransactionalOpenMlsStorage};
use crate::wire::{PROTOCOL_VERSION, proto};

struct RecoveryControl {
    group_id: GroupId,
    kind: RecoveryControlKind,
    recipient: Option<[u8; 32]>,
    payload: Vec<u8>,
}

impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_begin_group_recovery(
        &self,
        command_id: &str,
        recovery: &proto::BeginGroupRecovery,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let group_id = GroupId::from_bytes(
            recovery
                .group_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        );
        let stored = candidate
            .groups
            .iter()
            .find(|stored| stored.group_id.as_slice() == group_id.as_bytes())
            .cloned()
            .ok_or(Error::InvalidKey)?;
        if candidate
            .pending_group_mutations
            .iter()
            .any(|pending| pending.group_id == stored.group_id)
            || !candidate.pending_group_recoveries.is_empty()
        {
            return Err(Error::Mls("group recovery already pending"));
        }
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        if !policy.is_admin(local_identity) {
            return Err(Error::InvalidSignature);
        }
        let chain = CoordinatorChain::decode(
            &stored.coordinator_chain,
            policy.coordination_id(),
            policy.coordinator_public_key(),
        )
        .map_err(|_| Error::InvalidSignature)?;
        let proposal = RecoveryProposal::new(
            &policy,
            stored.epoch,
            chain.receipt_head(),
            recovery.replacement_relay_url.clone(),
            CoordinatorBinding::new(
                recovery
                    .replacement_coordination_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
                recovery
                    .replacement_coordinator_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
            ),
        )
        .map_err(|_| Error::InvalidKey)?;
        let mut endorsements = Vec::new();
        if policy.can_endorse_recovery(local_identity) {
            endorsements.push(RecoveryEndorsement::sign(&proposal, &self.identity)?.encode());
        }
        candidate
            .pending_group_recoveries
            .push(proto::PendingGroupRecovery {
                proposal: proposal.encode(),
                endorsements,
            });

        if policy
            .admins()
            .iter()
            .copied()
            .any(|admin| admin != local_identity && policy.can_endorse_recovery(admin))
        {
            self.stage_recovery_control(
                command_id,
                RecoveryControl {
                    group_id,
                    kind: RecoveryControlKind::Proposal,
                    recipient: None,
                    payload: proposal.encode(),
                },
                candidate,
                output,
            )?;
        }
        self.try_finalize_group_recovery(command_id, candidate, output)
    }

    pub(super) fn stage_apply_group_recovery_proposal(
        &self,
        command_id: &str,
        sender_identity: &[u8],
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let sender: [u8; 32] = sender_identity.try_into().map_err(|_| Error::InvalidKey)?;
        let proposal =
            RecoveryProposal::decode(&inbound.payload).map_err(|_| Error::InvalidSignature)?;
        let stored = candidate
            .groups
            .iter()
            .find(|stored| stored.group_id.as_slice() == proposal.group_id().as_slice())
            .cloned()
            .ok_or(Error::InvalidKey)?;
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        if !policy.is_admin(sender) {
            return Err(Error::InvalidSignature);
        }
        let chain = CoordinatorChain::decode(
            &stored.coordinator_chain,
            policy.coordination_id(),
            policy.coordinator_public_key(),
        )
        .map_err(|_| Error::InvalidSignature)?;
        proposal
            .verify(&policy, stored.epoch, chain.receipt_head())
            .map_err(|_| Error::InvalidSignature)?;
        let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        if !policy.can_endorse_recovery(local_identity) {
            return Err(Error::InvalidSignature);
        }
        let endorsement = RecoveryEndorsement::sign(&proposal, &self.identity)?;
        self.stage_recovery_control(
            command_id,
            RecoveryControl {
                group_id: GroupId::from_bytes(proposal.group_id()),
                kind: RecoveryControlKind::Endorsement,
                recipient: Some(sender),
                payload: endorsement.encode(),
            },
            candidate,
            output,
        )?;
        Ok(())
    }

    pub(super) fn stage_apply_group_recovery_endorsement(
        &self,
        command_id: &str,
        sender_identity: &[u8],
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let sender: [u8; 32] = sender_identity.try_into().map_err(|_| Error::InvalidKey)?;
        let endorsement =
            RecoveryEndorsement::decode(&inbound.payload).map_err(|_| Error::InvalidSignature)?;
        if endorsement.signer_identity() != sender {
            return Err(Error::InvalidSignature);
        }
        let pending = candidate
            .pending_group_recoveries
            .first_mut()
            .ok_or(Error::InvalidKey)?;
        if pending.endorsements.iter().any(|encoded| {
            RecoveryEndorsement::decode(encoded)
                .is_ok_and(|existing| existing.signer_identity() == sender)
        }) {
            return Ok(());
        }
        pending.endorsements.push(endorsement.encode());
        self.try_finalize_group_recovery(command_id, candidate, output)
    }

    fn try_finalize_group_recovery(
        &self,
        command_id: &str,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let Some(pending) = candidate.pending_group_recoveries.first().cloned() else {
            return Ok(());
        };
        let proposal =
            RecoveryProposal::decode(&pending.proposal).map_err(|_| Error::InvalidSignature)?;
        let endorsements = pending
            .endorsements
            .iter()
            .map(|encoded| RecoveryEndorsement::decode(encoded))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvalidSignature)?;
        if endorsements.is_empty() {
            return Ok(());
        }
        let certificate = RecoveryCertificate::new(proposal.clone(), endorsements)
            .map_err(|_| Error::InvalidSignature)?;
        let stored = candidate
            .groups
            .iter()
            .find(|stored| stored.group_id.as_slice() == proposal.group_id().as_slice())
            .ok_or(Error::InvalidKey)?;
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let chain = CoordinatorChain::decode(
            &stored.coordinator_chain,
            policy.coordination_id(),
            policy.coordinator_public_key(),
        )
        .map_err(|_| Error::InvalidSignature)?;
        match certificate.verify(&policy, stored.epoch, chain.receipt_head()) {
            Ok(()) => {}
            Err(RecoveryError::InsufficientQuorum) => return Ok(()),
            Err(_) => return Err(Error::InvalidSignature),
        }
        candidate.pending_group_recoveries.remove(0);
        self.stage_recover_group(
            command_id,
            &proto::RecoverGroup {
                recovery_certificate: certificate.encode(),
            },
            candidate,
            output,
        )
    }

    pub(super) fn stage_recover_group(
        &self,
        command_id: &str,
        recovery: &proto::RecoverGroup,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let certificate = RecoveryCertificate::decode(&recovery.recovery_certificate)
            .map_err(|_| Error::InvalidSignature)?;
        let group_index = candidate
            .groups
            .iter()
            .position(|stored| {
                stored.group_id.as_slice() == certificate.proposal().group_id().as_slice()
            })
            .ok_or(Error::InvalidKey)?;
        let stored = candidate.groups[group_index].clone();
        if candidate
            .pending_group_mutations
            .iter()
            .any(|pending| pending.group_id == stored.group_id)
        {
            return Err(Error::Mls("group mutation already pending"));
        }
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        if !policy.is_admin(local_identity) {
            return Err(Error::InvalidSignature);
        }
        let chain = CoordinatorChain::decode(
            &stored.coordinator_chain,
            policy.coordination_id(),
            policy.coordinator_public_key(),
        )
        .map_err(|_| Error::InvalidSignature)?;
        certificate
            .verify(&policy, stored.epoch, chain.receipt_head())
            .map_err(|_| Error::InvalidSignature)?;

        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
        let pending = engine.stage_recovery(
            &self.identity,
            &mut mls_storage,
            &certificate,
            chain.receipt_head(),
        )?;
        let mutation =
            GroupMutationCandidate::with_recovery(pending.commit().to_vec(), certificate.encode())?;
        let next_epoch = stored.epoch.checked_add(1).ok_or(Error::Serialization)?;
        let registration =
            GroupRelayRegistration::create(&self.identity, pending.next_policy(), next_epoch)?;

        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        candidate
            .pending_group_mutations
            .push(proto::PendingGroupMutation {
                group_id: stored.group_id,
                base_epoch: stored.epoch,
                commit: pending.commit().to_vec(),
                next_policy: pending.next_policy().encode(),
                event_kind: proto::GroupPolicyChangeKind::RelayChanged as i32,
                actor_identity: pending.event().actor.to_vec(),
                subject_identity: Vec::new(),
                welcome: Vec::new(),
                welcome_destination: Vec::new(),
                coordinator_candidate: mutation.encode(),
            });
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: format!("{command_id}:register-replacement"),
                kind: proto::OutboundKind::GroupRelayRegistration as i32,
                relay_url: pending.next_policy().relay_url().to_owned(),
                destination: pending.next_policy().coordination_id().to_vec(),
                payload: registration.encode(),
                local_only: false,
            },
        });
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: format!("{command_id}:coordinate-recovery"),
                kind: proto::OutboundKind::GroupCoordinator as i32,
                relay_url: pending.next_policy().relay_url().to_owned(),
                destination: pending.next_policy().coordination_id().to_vec(),
                payload: proto::GroupCoordinatorSubmission {
                    version: PROTOCOL_VERSION,
                    claimed_base_epoch: stored.epoch,
                    candidate: mutation.encode(),
                }
                .encode_to_vec(),
                local_only: false,
            },
        });
        Ok(())
    }

    fn stage_recovery_control(
        &self,
        command_id: &str,
        control: RecoveryControl,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let stored = candidate
            .groups
            .iter()
            .find(|stored| stored.group_id.as_slice() == control.group_id.as_bytes())
            .cloned()
            .ok_or(Error::InvalidKey)?;
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
        let ciphertext = engine.encrypt_application(
            &self.identity,
            &mut mls_storage,
            GroupApplication::recovery_control(control.kind, control.recipient, control.payload),
        )?;
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: format!("{command_id}:recovery-control"),
                kind: proto::OutboundKind::GroupMessage as i32,
                relay_url: stored.relay_url,
                destination: engine.policy().coordination_id().to_vec(),
                payload: ciphertext.encode(),
                local_only: false,
            },
        });
        Ok(())
    }
}
