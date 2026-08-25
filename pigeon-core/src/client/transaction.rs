use prost::Message;
use sha2::{Digest, Sha256};

use crate::Error;
use crate::client::{AppEvent, ClientCommand, ClientOutput, OutboundItem};
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::storage::{SealedCheckpoint, StateStore, StorageError};
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
            _ => return Err(Error::MalformedBundle),
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

    pub fn store(&self) -> &S {
        &self.store
    }

    fn stage_create_group(
        &self,
        command_id: &str,
        create: &proto::CreateGroup,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let owner = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let mut group_id = [0u8; 32];
        getrandom::getrandom(&mut group_id).map_err(|_| Error::Entropy)?;
        candidate.groups.push(proto::StoredGroup {
            group_id: group_id.to_vec(),
            owner_identity: owner.to_vec(),
            name: create.name.clone(),
            member_identities: create.member_identities.clone(),
            relay_url: create.relay_url.clone(),
            mesh_enabled: create.mesh_enabled,
            epoch: 0,
            policy_revision: 0,
        });

        output.events.push(AppEvent {
            inner: proto::AppEvent {
                version: PROTOCOL_VERSION,
                event_id: format!("{command_id}:pending"),
                body: Some(proto::app_event::Body::GroupDeliveryChanged(
                    proto::GroupDeliveryChanged {
                        group_id: group_id.to_vec(),
                        message_id: String::new(),
                        state: proto::GroupDeliveryState::Pending as i32,
                        epoch: 0,
                    },
                )),
            },
        });
        output
            .outbound
            .extend(
                create
                    .member_identities
                    .iter()
                    .enumerate()
                    .map(|(index, member)| OutboundItem {
                        inner: proto::OutboundItem {
                            item_id: format!("{command_id}:key-package:{index}"),
                            kind: proto::OutboundKind::KeyPackageRequest as i32,
                            relay_url: create.relay_url.clone(),
                            destination: member.clone(),
                            payload: Vec::new(),
                        },
                    }),
            );
        Ok(())
    }
}

fn encode_checkpoint(state: &proto::ClientCheckpoint) -> SealedCheckpoint {
    let bytes = state.encode_to_vec();
    let sha256 = Sha256::digest(&bytes).into();
    SealedCheckpoint {
        generation: state.generation,
        bytes,
        sha256,
    }
}

fn decode_checkpoint(checkpoint: SealedCheckpoint) -> Result<proto::ClientCheckpoint, Error> {
    if Sha256::digest(&checkpoint.bytes).as_slice() != checkpoint.sha256 {
        return Err(Error::Persistence(StorageError::Corrupt));
    }
    let state = proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice())
        .map_err(|_| Error::Persistence(StorageError::Corrupt))?;
    if state.version != PROTOCOL_VERSION || state.generation != checkpoint.generation {
        return Err(Error::Persistence(StorageError::Corrupt));
    }
    Ok(state)
}
