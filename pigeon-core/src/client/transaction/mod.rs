mod checkpoint;
mod group_creation;
mod group_messaging;
mod group_policy;

use checkpoint::{decode_checkpoint, encode_checkpoint};

use crate::Error;
use crate::client::{ClientCommand, ClientOutput, ClientSnapshot};
use crate::group::PigeonGroupPolicy;
use crate::identity::SecureIdentity;
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
        Ok(ClientSnapshot {
            inner: proto::ClientSnapshot {
                checkpoint_generation: self.state.generation,
                groups,
            },
        })
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
