use prost::Message;

use super::PigeonClient;
use super::checkpoint::stored_group;

use crate::Error;
use crate::client::{AppEvent, ClientOutput, OutboundItem};
use crate::group::{
    CoordinatorBinding, GroupCreationConfig, GroupEngine, GroupId, GroupMutationCandidate,
    GroupRelayRegistration, PigeonGroupPolicy,
};
use crate::identity::{GroupJoinMaterial, GroupJoinRequest, IdentityPurpose, SecureIdentity};
use crate::storage::{StateStore, TransactionalOpenMlsStorage};
use crate::wire::{PROTOCOL_VERSION, proto};

impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_create_group(
        &self,
        command_id: &str,
        create: &proto::CreateGroup,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let owner = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let mut group_id = [0_u8; 32];
        let mut coordination_id = [0_u8; 32];
        getrandom::getrandom(&mut group_id).map_err(|_| Error::Entropy)?;
        getrandom::getrandom(&mut coordination_id).map_err(|_| Error::Entropy)?;
        let group_id = GroupId::from_bytes(group_id);
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
        PigeonGroupPolicy::validate_draft(
            owner,
            members,
            &create.name,
            &create.relay_url,
            CoordinatorBinding::new(
                coordination_id,
                create
                    .coordinator_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
            ),
        )?;
        let request = GroupJoinRequest::create(
            &self.identity,
            group_id,
            coordination_id,
            create.relay_url.clone(),
        )?;
        let request_payload = request.encode();
        let request_ids: Vec<_> = (0..create.member_identities.len())
            .map(|index| format!("{command_id}:join:{index}"))
            .collect();
        candidate
            .pending_group_creations
            .push(proto::PendingGroupCreation {
                command_id: command_id.to_owned(),
                name: create.name.clone(),
                member_identities: create.member_identities.clone(),
                relay_url: create.relay_url.clone(),
                mesh_enabled: create.mesh_enabled,
                join_materials: vec![Vec::new(); create.member_identities.len()],
                join_request_ids: request_ids.clone(),
                coordinator_public_key: create.coordinator_public_key.clone(),
                group_id: group_id.as_bytes().to_vec(),
                coordination_id: coordination_id.to_vec(),
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
                        kind: proto::OutboundKind::GroupJoinRequest as i32,
                        relay_url: create.relay_url.clone(),
                        destination: member.clone(),
                        payload: request_payload.clone(),
                    },
                }),
        );
        Ok(())
    }

    pub(super) fn stage_apply_group_join_request(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let request = GroupJoinRequest::decode(&inbound.payload)?;
        let mut mls_storage = if candidate.openmls_checkpoint.is_empty() {
            TransactionalOpenMlsStorage::new()
        } else {
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?
        };
        let material = GroupJoinMaterial::issue_for(
            &self.identity,
            request.requester_identity(),
            request.owner_identity(),
            request.group_id(),
            request.coordination_id(),
            &mut mls_storage,
        )?;
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: format!("{command_id}:material"),
                kind: proto::OutboundKind::GroupJoinMaterial as i32,
                relay_url: request.relay_url().to_owned(),
                destination: request.requester_identity().to_vec(),
                payload: material.encode(),
            },
        });
        Ok(())
    }

    pub(super) fn stage_apply_group_join_material(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let owner = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let material = GroupJoinMaterial::decode(&inbound.payload)?;
        let canonical_material = material.encode();
        if candidate
            .consumed_key_package_hashes
            .iter()
            .any(|hash| hash.as_slice() == material.package_hash())
            || candidate
                .pending_group_creations
                .iter()
                .flat_map(|draft| &draft.join_materials)
                .any(|stored| stored == &canonical_material)
        {
            return Err(Error::InvalidSignature);
        }
        if self.stage_apply_group_addition_material(
            command_id, inbound, &material, candidate, output,
        )? {
            return Ok(());
        }
        let draft_index = candidate
            .pending_group_creations
            .iter()
            .position(|draft| {
                draft
                    .join_request_ids
                    .iter()
                    .any(|request| request == &inbound.request_id)
            })
            .ok_or(Error::InvalidKey)?;
        let draft = &mut candidate.pending_group_creations[draft_index];
        let material_index = draft
            .join_request_ids
            .iter()
            .position(|request| request == &inbound.request_id)
            .ok_or(Error::InvalidKey)?;
        let group_id = GroupId::from_bytes(
            draft
                .group_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        );
        let coordination_id = draft
            .coordination_id
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        material.verify_for(owner, group_id, coordination_id)?;
        if !draft.join_materials[material_index].is_empty()
            || draft.member_identities[material_index].as_slice() != material.member_identity()
        {
            return Err(Error::InvalidSignature);
        }
        draft.join_materials[material_index] = canonical_material;
        if draft
            .join_materials
            .iter()
            .any(|material| material.is_empty())
        {
            return Ok(());
        }

        let draft = candidate.pending_group_creations.remove(draft_index);
        let materials = draft
            .join_materials
            .iter()
            .map(|bytes| GroupJoinMaterial::decode(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let consumed_hashes: Vec<_> = materials
            .iter()
            .map(|material| material.package_hash().to_vec())
            .collect();
        let registration = GroupRelayRegistration::create(
            &self.identity,
            group_id,
            coordination_id,
            materials
                .iter()
                .map(GroupJoinMaterial::capability_public_key),
        )?;
        let mut mls_storage = if candidate.openmls_checkpoint.is_empty() {
            TransactionalOpenMlsStorage::new()
        } else {
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?
        };
        let (engine, initial_commit, welcome) = GroupEngine::create_configured(
            &self.identity,
            &mut mls_storage,
            GroupCreationConfig {
                group_id,
                name: draft.name,
                relay_url: draft.relay_url,
                coordinator: CoordinatorBinding::new(
                    coordination_id,
                    draft
                        .coordinator_public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::InvalidKey)?,
                ),
                mesh_enabled: draft.mesh_enabled,
            },
            materials,
        )?;
        candidate
            .consumed_key_package_hashes
            .extend(consumed_hashes);
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        let policy = engine.policy();
        candidate.groups.push(stored_group(&engine));
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
                kind: proto::OutboundKind::GroupRelayRegistration as i32,
                relay_url: policy.relay_url().to_owned(),
                destination: policy.coordination_id().to_vec(),
                payload: registration.encode(),
            },
        });
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: format!("{command_id}:coordinate"),
                kind: proto::OutboundKind::GroupCoordinator as i32,
                relay_url: policy.relay_url().to_owned(),
                destination: policy.coordination_id().to_vec(),
                payload: proto::GroupCoordinatorSubmission {
                    version: PROTOCOL_VERSION,
                    claimed_base_epoch: 0,
                    candidate: GroupMutationCandidate::new(Vec::new(), initial_commit)?.encode(),
                }
                .encode_to_vec(),
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
                            kind: proto::OutboundKind::GroupWelcome as i32,
                            relay_url: policy.relay_url().to_owned(),
                            destination: member,
                            payload: welcome.clone(),
                        },
                    }),
            );
        Ok(())
    }

    pub(super) fn stage_apply_group_welcome(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let mut mls_storage = if candidate.openmls_checkpoint.is_empty() {
            TransactionalOpenMlsStorage::new()
        } else {
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?
        };
        let engine = GroupEngine::join_welcome(&self.identity, &mut mls_storage, &inbound.payload)?;
        if candidate
            .groups
            .iter()
            .any(|group| group.group_id.as_slice() == engine.group_id().as_bytes())
        {
            return Err(Error::InvalidSignature);
        }
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        let policy = engine.policy();
        candidate.groups.push(stored_group(&engine));
        output.events.push(AppEvent {
            inner: proto::AppEvent {
                version: PROTOCOL_VERSION,
                event_id: format!("{command_id}:joined"),
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
        Ok(())
    }
}
