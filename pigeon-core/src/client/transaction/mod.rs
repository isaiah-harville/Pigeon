mod checkpoint;
mod group_creation;
mod group_messaging;
mod group_policy;
mod pairwise;

use checkpoint::{decode_checkpoint, encode_checkpoint};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::client::{ClientCommand, ClientOutput, ClientSnapshot};
use crate::group::{PigeonGroupPolicy, group_relay_challenge_transcript};
use crate::identity::PlatformAccount;
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::storage::StateStore;
use crate::wire::{PROTOCOL_VERSION, proto};

pub struct PigeonClient<S, I> {
    store: S,
    identity: I,
    state: proto::ClientCheckpoint,
}

impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub fn new(store: S, identity: I) -> Result<Self, Error> {
        let state = match store.load()? {
            Some(checkpoint) => decode_checkpoint(checkpoint)?,
            None => proto::ClientCheckpoint {
                version: PROTOCOL_VERSION,
                generation: 0,
                applied_command_ids: Vec::new(),
                groups: Vec::new(),
                openmls_checkpoint: Vec::new(),
                pending_group_creations: Vec::new(),
                consumed_key_package_hashes: Vec::new(),
                processed_group_messages: Vec::new(),
                delivery_ledgers: Vec::new(),
                buffered_group_messages: Vec::new(),
                pending_group_mutations: Vec::new(),
                pending_group_additions: Vec::new(),
                pending_outbound: Vec::new(),
                pending_events: Vec::new(),
                pairwise_account_state: Vec::new(),
                pairwise_fallback_key: Vec::new(),
                pairwise_contacts: Vec::new(),
                pairwise_sessions: Vec::new(),
                consumed_pairwise_envelope_hashes: Vec::new(),
            },
        };
        Ok(Self {
            store,
            identity,
            state,
        })
    }

    pub fn execute(&mut self, command: ClientCommand) -> Result<ClientOutput, Error> {
        if self
            .state
            .applied_command_ids
            .iter()
            .any(|existing| existing == command.command_id())
        {
            return Ok(ClientOutput::empty(self.state.generation));
        }

        let mut candidate = self.state.clone();
        let mut output = ClientOutput::empty(candidate.generation + 1);
        match command.inner.body.as_ref().ok_or(Error::MalformedBundle)? {
            proto::client_command::Body::CreateGroup(create) => {
                self.stage_create_group(
                    &command.inner.command_id,
                    create,
                    &mut candidate,
                    &mut output,
                )?;
            }
            proto::client_command::Body::ApplyInbound(inbound) => {
                self.stage_apply_inbound(
                    &command.inner.command_id,
                    inbound,
                    &mut candidate,
                    &mut output,
                )?;
            }
            proto::client_command::Body::SendGroupMessage(send) => {
                self.stage_send_group_message(
                    &command.inner.command_id,
                    send,
                    &mut candidate,
                    &mut output,
                )?;
            }
            proto::client_command::Body::ChangeGroupPolicy(change) => {
                self.stage_change_group_policy(
                    &command.inner.command_id,
                    change,
                    &mut candidate,
                    &mut output,
                )?;
            }
            proto::client_command::Body::AcknowledgeEffects(acknowledgement) => {
                candidate.pending_outbound.retain(|item| {
                    !acknowledgement
                        .outbound_item_ids
                        .iter()
                        .any(|id| id == &item.item_id)
                });
                candidate.pending_events.retain(|event| {
                    !acknowledgement
                        .event_ids
                        .iter()
                        .any(|id| id == &event.event_id)
                });
            }
            proto::client_command::Body::EnsurePairwiseAccount(_) => {
                if candidate.pairwise_account_state.is_empty()
                    && candidate.pairwise_fallback_key.is_empty()
                {
                    let account = PlatformAccount::new();
                    candidate.pairwise_account_state = account.export_state()?;
                    candidate.pairwise_fallback_key = account.export_fallback_key().to_vec();
                } else {
                    pairwise_account(&candidate)?;
                }
            }
            proto::client_command::Body::RegisterPairwiseContact(register) => {
                self.stage_register_pairwise_contact(register, &mut candidate)?;
            }
            proto::client_command::Body::SendPairwiseControl(send) => {
                self.stage_send_pairwise_control(
                    &command.inner.command_id,
                    send,
                    &mut candidate,
                    &mut output,
                )?;
            }
        }

        self.stage_wrap_addressed_controls(&mut candidate, &mut output)?;

        if candidate.pending_outbound.len() + output.outbound.len()
            > crate::MAX_PENDING_OUTBOUND_ENTRIES
            || candidate.pending_events.len() + output.events.len()
                > crate::MAX_PENDING_OUTBOUND_ENTRIES
        {
            return Err(Error::ResourceLimit("pending core effects"));
        }
        candidate
            .pending_outbound
            .extend(output.outbound.iter().map(|item| item.inner.clone()));
        candidate
            .pending_events
            .extend(output.events.iter().map(|event| event.inner.clone()));
        let pending_effect_bytes = candidate
            .pending_outbound
            .iter()
            .map(prost::Message::encoded_len)
            .chain(
                candidate
                    .pending_events
                    .iter()
                    .map(prost::Message::encoded_len),
            )
            .sum::<usize>();
        if pending_effect_bytes > crate::wire::MAX_PENDING_EFFECT_BYTES {
            return Err(Error::ResourceLimit("pending core effect bytes"));
        }

        candidate.generation += 1;
        candidate
            .applied_command_ids
            .push(command.inner.command_id.clone());
        let checkpoint = encode_checkpoint(&candidate);
        self.store.replace(self.state.generation, checkpoint)?;

        self.state = candidate;
        Ok(output)
    }

    pub fn checkpoint_generation(&self) -> u64 {
        self.state.generation
    }

    /// Returns the durable application projection without mutating or replacing
    /// the checkpoint. Hosts use this to rebuild UI state after a crash or
    /// relaunch; the core checkpoint remains the sole group-state authority.
    pub fn snapshot(&self) -> Result<ClientSnapshot, Error> {
        let local_identity = self
            .identity
            .ensure_public_key(crate::IdentityPurpose::Root)?;
        let groups = self
            .state
            .groups
            .iter()
            .map(|stored| {
                let policy = PigeonGroupPolicy::decode(&stored.policy)?;
                Ok(proto::GroupState {
                    group_id: policy.group_id().as_bytes().to_vec(),
                    owner_identity: policy.owner().to_vec(),
                    admin_identities: policy
                        .admins()
                        .iter()
                        .map(|identity| identity.to_vec())
                        .collect(),
                    member_identities: policy
                        .members()
                        .iter()
                        .map(|identity| identity.to_vec())
                        .collect(),
                    name: policy.name().to_owned(),
                    relay_url: policy.relay_url().to_owned(),
                    coordination_id: policy.coordination_id().to_vec(),
                    mesh_enabled: policy.mesh_enabled(),
                    epoch: stored.epoch,
                    policy_revision: policy.revision(),
                    dissolved: policy.dissolved(),
                    capability_public_key: policy
                        .member_capability_key(local_identity)
                        .map_or_else(Vec::new, |key| key.to_vec()),
                    coordinator_public_key: policy.coordinator_public_key().to_vec(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let pairwise_prekey_bundle = pairwise_account(&self.state)?
            .map(|account| account.signed_prekey_bundle(&self.identity))
            .transpose()?
            .map_or_else(Vec::new, |bundle| bundle.encode());
        Ok(ClientSnapshot {
            inner: proto::ClientSnapshot {
                checkpoint_generation: self.state.generation,
                groups,
                pending_outbound: self.state.pending_outbound.clone(),
                pending_events: self.state.pending_events.clone(),
                pairwise_prekey_bundle,
            },
        })
    }

    /// Signs the relay's group-capability challenge inside the identity/core
    /// boundary. The host supplies only the authenticated group id and nonce;
    /// it never constructs the signed transcript or handles the private key.
    pub fn sign_group_relay_challenge(
        &self,
        group_id: crate::GroupId,
        nonce: [u8; 32],
    ) -> Result<[u8; 64], Error> {
        let stored = self
            .state
            .groups
            .iter()
            .find(|stored| stored.group_id.as_slice() == group_id.as_bytes())
            .ok_or(Error::InvalidKey)?;
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let policy_capability = policy
            .member_capability_key(local_identity)
            .ok_or(Error::InvalidKey)?;
        let signing_capability = self
            .identity
            .ensure_public_key(IdentityPurpose::GroupCapability(*group_id.as_bytes()))?;
        if policy_capability != signing_capability {
            return Err(Error::InvalidSignature);
        }
        self.identity
            .sign(
                IdentityPurpose::GroupCapability(*group_id.as_bytes()),
                &group_relay_challenge_transcript(
                    policy.coordination_id(),
                    policy_capability,
                    nonce,
                ),
            )
            .map_err(Error::from)
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    fn stage_apply_inbound(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        match proto::OutboundKind::try_from(inbound.kind).map_err(|_| Error::MalformedBundle)? {
            proto::OutboundKind::Pairwise => {
                let envelope_hash = Sha256::digest(&inbound.payload).to_vec();
                if candidate
                    .consumed_pairwise_envelope_hashes
                    .contains(&envelope_hash)
                {
                    return Ok(());
                }
                let control = self.stage_apply_pairwise_control(inbound, candidate)?;
                let inner = proto::ApplyInbound {
                    kind: i32::try_from(control.content_kind)
                        .map_err(|_| Error::MalformedBundle)?,
                    payload: control.payload,
                    request_id: inbound.request_id.clone(),
                };
                match proto::OutboundKind::try_from(inner.kind)
                    .map_err(|_| Error::MalformedBundle)?
                {
                    proto::OutboundKind::GroupJoinRequest => {
                        self.stage_apply_group_join_request(command_id, &inner, candidate, output)
                    }
                    proto::OutboundKind::GroupJoinMaterial => {
                        self.stage_apply_group_join_material(command_id, &inner, candidate, output)
                    }
                    proto::OutboundKind::GroupWelcome => {
                        self.stage_apply_group_welcome(command_id, &inner, candidate, output)
                    }
                    _ => Err(Error::MalformedBundle),
                }?;
                if candidate.consumed_pairwise_envelope_hashes.len()
                    >= crate::MAX_PENDING_OUTBOUND_ENTRIES
                {
                    candidate.consumed_pairwise_envelope_hashes.remove(0);
                }
                candidate
                    .consumed_pairwise_envelope_hashes
                    .push(envelope_hash);
                Ok(())
            }
            proto::OutboundKind::GroupJoinRequest => {
                self.stage_apply_group_join_request(command_id, inbound, candidate, output)
            }
            proto::OutboundKind::GroupJoinMaterial => {
                self.stage_apply_group_join_material(command_id, inbound, candidate, output)
            }
            proto::OutboundKind::GroupWelcome => {
                self.stage_apply_group_welcome(command_id, inbound, candidate, output)
            }
            proto::OutboundKind::GroupMessage => {
                self.stage_apply_group_message(command_id, inbound, candidate, output)
            }
            proto::OutboundKind::GroupCoordinator => {
                self.stage_apply_group_coordinator(command_id, inbound, candidate, output)
            }
            proto::OutboundKind::GroupLeaveProposal => {
                self.stage_apply_group_leave_proposal(command_id, inbound, candidate, output)
            }
            _ => Err(Error::MalformedBundle),
        }
    }
}

fn pairwise_account(state: &proto::ClientCheckpoint) -> Result<Option<PlatformAccount>, Error> {
    match (
        state.pairwise_account_state.is_empty(),
        state.pairwise_fallback_key.is_empty(),
    ) {
        (true, true) => Ok(None),
        (false, false) => {
            let fallback_key = state
                .pairwise_fallback_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Serialization)?;
            Ok(Some(PlatformAccount::import(
                &state.pairwise_account_state,
                fallback_key,
            )?))
        }
        _ => Err(Error::Serialization),
    }
}
