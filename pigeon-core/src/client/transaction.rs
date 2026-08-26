use prost::Message;
use sha2::{Digest, Sha256};

use crate::Error;
use crate::client::{AppEvent, ClientCommand, ClientOutput, OutboundItem};
use crate::group::{GroupEngine, GroupId, PigeonGroupPolicy};
use crate::identity::{IdentityPurpose, ReservedKeyPackage, SecureIdentity};
use crate::storage::TransactionalOpenMlsStorage;
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
                openmls_checkpoint: Vec::new(),
                pending_group_creations: Vec::new(),
                consumed_key_package_hashes: Vec::new(),
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
        let members = create
            .member_identities
            .iter()
            .map(|identity| {
                identity
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)
            })
            .collect::<Result<Vec<[u8; 32]>, _>>()?;
        PigeonGroupPolicy::new(
            GroupId::from_bytes([0; 32]),
            owner,
            members,
            create.name.clone(),
            create.relay_url.clone(),
            [0; 32],
        )?;
        let request_ids: Vec<_> = (0..create.member_identities.len())
            .map(|index| format!("{command_id}:key-package:{index}"))
            .collect();
        candidate
            .pending_group_creations
            .push(proto::PendingGroupCreation {
                command_id: command_id.to_owned(),
                name: create.name.clone(),
                member_identities: create.member_identities.clone(),
                relay_url: create.relay_url.clone(),
                mesh_enabled: create.mesh_enabled,
                reserved_key_packages: vec![Vec::new(); create.member_identities.len()],
                key_package_request_ids: request_ids.clone(),
            });
        output.outbound.extend(
            create
                .member_identities
                .iter()
                .enumerate()
                .zip(request_ids)
                .map(|((_, member), request_id)| OutboundItem {
                    inner: proto::OutboundItem {
                        item_id: request_id,
                        kind: proto::OutboundKind::KeyPackageRequest as i32,
                        relay_url: create.relay_url.clone(),
                        destination: member.clone(),
                        payload: Vec::new(),
                    },
                }),
        );
        Ok(())
    }

    fn stage_apply_inbound(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        if proto::OutboundKind::try_from(inbound.kind) != Ok(proto::OutboundKind::KeyPackage) {
            return Err(Error::MalformedBundle);
        }
        let owner = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let package = ReservedKeyPackage::decode(&inbound.payload)?;
        package.verify_for(owner)?;
        let canonical_package = package.encode();
        if candidate
            .consumed_key_package_hashes
            .iter()
            .any(|hash| hash.as_slice() == package.package_hash())
            || candidate
                .pending_group_creations
                .iter()
                .flat_map(|draft| &draft.reserved_key_packages)
                .any(|stored| stored == &canonical_package)
        {
            return Err(Error::InvalidSignature);
        }
        let draft_index = candidate
            .pending_group_creations
            .iter()
            .position(|draft| {
                draft
                    .key_package_request_ids
                    .iter()
                    .any(|request| request == &inbound.request_id)
            })
            .ok_or(Error::InvalidKey)?;
        let draft = &mut candidate.pending_group_creations[draft_index];
        let package_index = draft
            .key_package_request_ids
            .iter()
            .position(|request| request == &inbound.request_id)
            .ok_or(Error::InvalidKey)?;
        if !draft.reserved_key_packages[package_index].is_empty()
            || draft.member_identities[package_index].as_slice() != package.issuer()
        {
            return Err(Error::InvalidSignature);
        }
        draft.reserved_key_packages[package_index] = canonical_package;
        if draft
            .reserved_key_packages
            .iter()
            .any(|package| package.is_empty())
        {
            return Ok(());
        }

        let draft = candidate.pending_group_creations.remove(draft_index);
        let packages = draft
            .reserved_key_packages
            .iter()
            .map(|bytes| ReservedKeyPackage::decode(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let consumed_hashes: Vec<_> = packages
            .iter()
            .map(|package| package.package_hash().to_vec())
            .collect();
        let mut coordination_id = [0_u8; 32];
        getrandom::getrandom(&mut coordination_id).map_err(|_| Error::Entropy)?;
        let mut mls_storage = if candidate.openmls_checkpoint.is_empty() {
            TransactionalOpenMlsStorage::new()
        } else {
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?
        };
        let (engine, initial_commit, welcome) = GroupEngine::create_with_mesh(
            &self.identity,
            &mut mls_storage,
            draft.name,
            draft.relay_url,
            coordination_id,
            packages,
            draft.mesh_enabled,
        )?;
        candidate
            .consumed_key_package_hashes
            .extend(consumed_hashes);
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        let policy = engine.policy();
        candidate.groups.push(proto::StoredGroup {
            group_id: engine.group_id().as_bytes().to_vec(),
            owner_identity: policy.owner().to_vec(),
            name: policy.name().to_owned(),
            member_identities: policy
                .members()
                .iter()
                .map(|identity| identity.to_vec())
                .collect(),
            relay_url: policy.relay_url().to_owned(),
            mesh_enabled: policy.mesh_enabled(),
            epoch: engine.epoch(),
            policy_revision: policy.revision(),
            policy: policy.encode(),
        });
        output.events.push(AppEvent {
            inner: proto::AppEvent {
                version: PROTOCOL_VERSION,
                event_id: format!("{command_id}:created"),
                body: Some(proto::app_event::Body::GroupCreated(proto::GroupCreated {
                    group_id: engine.group_id().as_bytes().to_vec(),
                    owner_identity: policy.owner().to_vec(),
                    name: policy.name().to_owned(),
                    relay_url: policy.relay_url().to_owned(),
                    mesh_enabled: policy.mesh_enabled(),
                    epoch: engine.epoch(),
                    policy_revision: policy.revision(),
                })),
            },
        });
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: format!("{command_id}:register"),
                kind: proto::OutboundKind::GroupCoordinator as i32,
                relay_url: policy.relay_url().to_owned(),
                destination: policy.coordination_id().to_vec(),
                payload: initial_commit,
            },
        });
        output
            .outbound
            .extend(
                draft
                    .member_identities
                    .into_iter()
                    .enumerate()
                    .map(|(index, member)| OutboundItem {
                        inner: proto::OutboundItem {
                            item_id: format!("{command_id}:welcome:{index}"),
                            kind: proto::OutboundKind::GroupCoordinator as i32,
                            relay_url: policy.relay_url().to_owned(),
                            destination: member,
                            payload: welcome.clone(),
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
