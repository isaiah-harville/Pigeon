use prost::Message;
use sha2::{Digest, Sha256};

use crate::Error;
use crate::client::{AppEvent, ClientCommand, ClientOutput, OutboundItem};
use crate::group::{CoordinatorBinding, GroupApplication, GroupEngine, GroupId, PigeonGroupPolicy};
use crate::identity::{IdentityPurpose, ReservedKeyPackage, SecureIdentity};
use crate::storage::TransactionalOpenMlsStorage;
use crate::storage::{SealedCheckpoint, StateStore, StorageError};
use crate::wire::{
    MAX_FUTURE_EPOCH_BUFFER_BYTES, MAX_FUTURE_EPOCHS, MAX_PENDING_OUTBOUND_ENTRIES,
    PROTOCOL_VERSION, proto,
};

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
            CoordinatorBinding::new(
                [0; 32],
                create
                    .coordinator_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
            ),
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
                coordinator_public_key: create.coordinator_public_key.clone(),
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
        match proto::OutboundKind::try_from(inbound.kind).map_err(|_| Error::MalformedBundle)? {
            proto::OutboundKind::KeyPackage => {
                self.stage_apply_key_package(command_id, inbound, candidate, output)
            }
            proto::OutboundKind::GroupWelcome => {
                self.stage_apply_group_welcome(command_id, inbound, candidate, output)
            }
            proto::OutboundKind::GroupMessage => {
                self.stage_apply_group_message(command_id, inbound, candidate, output)
            }
            _ => Err(Error::MalformedBundle),
        }
    }

    fn stage_apply_key_package(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
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
            CoordinatorBinding::new(
                coordination_id,
                draft
                    .coordinator_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
            ),
            packages,
            draft.mesh_enabled,
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
                            kind: proto::OutboundKind::GroupWelcome as i32,
                            relay_url: policy.relay_url().to_owned(),
                            destination: member,
                            payload: welcome.clone(),
                        },
                    }),
            );
        Ok(())
    }

    fn stage_apply_group_welcome(
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

    fn stage_apply_group_message(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let ciphertext = crate::GroupCiphertext::decode(&inbound.payload)?;
        if candidate.processed_group_messages.iter().any(|processed| {
            processed.group_id.as_slice() == ciphertext.group_id().as_bytes()
                && processed.message_id.as_slice() == ciphertext.message_id().as_bytes()
        }) {
            return Ok(());
        }
        let stored = candidate
            .groups
            .iter()
            .find(|group| group.group_id.as_slice() == ciphertext.group_id().as_bytes())
            .cloned()
            .ok_or(Error::InvalidKey)?;
        let buffered_index = candidate
            .buffered_group_messages
            .iter()
            .position(|buffered| {
                buffered.group_id.as_slice() == ciphertext.group_id().as_bytes()
                    && buffered.message_id.as_slice() == ciphertext.message_id().as_bytes()
            });
        if ciphertext.epoch() > stored.epoch {
            if buffered_index.is_some() {
                return Ok(());
            }
            self.stage_future_group_message(
                command_id,
                inbound,
                &stored,
                &ciphertext,
                candidate,
                output,
            )?;
            return Ok(());
        }
        if let Some(index) = buffered_index {
            candidate.buffered_group_messages.remove(index);
        }
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
        let received = engine.decrypt_application(&mut mls_storage, &ciphertext)?;
        if candidate.processed_group_messages.len() >= MAX_PENDING_OUTBOUND_ENTRIES {
            candidate.processed_group_messages.remove(0);
        }
        candidate
            .processed_group_messages
            .push(proto::ProcessedGroupMessage {
                group_id: ciphertext.group_id().as_bytes().to_vec(),
                message_id: ciphertext.message_id().as_bytes().to_vec(),
            });
        match received.application() {
            GroupApplication::Text { body, reply_to, .. } => {
                output.events.push(AppEvent {
                    inner: proto::AppEvent {
                        version: PROTOCOL_VERSION,
                        event_id: format!("{command_id}:received"),
                        body: Some(proto::app_event::Body::GroupMessageReceived(
                            proto::GroupMessageReceived {
                                group_id: received.group_id().as_bytes().to_vec(),
                                message_id: encode_message_id(received.message_id().as_bytes()),
                                sender_identity: received.sender_identity().to_vec(),
                                body: body.clone(),
                                reply_to_message_id: reply_to
                                    .map(|id| encode_message_id(id.as_bytes()))
                                    .unwrap_or_default(),
                                epoch: received.epoch(),
                            },
                        )),
                    },
                });
                let acknowledgement = engine.encrypt_application(
                    &self.identity,
                    &mut mls_storage,
                    GroupApplication::acknowledgement(
                        received.sender_identity(),
                        received.message_id(),
                        0,
                    ),
                )?;
                output.outbound.push(OutboundItem {
                    inner: proto::OutboundItem {
                        item_id: format!("{command_id}:ack"),
                        kind: proto::OutboundKind::GroupMessage as i32,
                        relay_url: stored.relay_url,
                        destination: engine.policy().coordination_id().to_vec(),
                        payload: acknowledgement.encode(),
                    },
                });
            }
            GroupApplication::Reaction {
                target, reaction, ..
            } => output.events.push(AppEvent {
                inner: proto::AppEvent {
                    version: PROTOCOL_VERSION,
                    event_id: format!("{command_id}:reaction"),
                    body: Some(proto::app_event::Body::GroupReactionReceived(
                        proto::GroupReactionReceived {
                            group_id: received.group_id().as_bytes().to_vec(),
                            message_id: encode_message_id(received.message_id().as_bytes()),
                            sender_identity: received.sender_identity().to_vec(),
                            target_message_id: encode_message_id(target.as_bytes()),
                            reaction: reaction.clone(),
                            epoch: received.epoch(),
                        },
                    )),
                },
            }),
            GroupApplication::Acknowledgement {
                original_sender,
                message_id,
                ..
            } => {
                let Some((state, delivered, intended)) = apply_delivery_acknowledgement(
                    candidate,
                    received.group_id(),
                    received.sender_identity(),
                    *original_sender,
                    *message_id,
                )?
                else {
                    candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
                    return Ok(());
                };
                output.events.push(AppEvent {
                    inner: proto::AppEvent {
                        version: PROTOCOL_VERSION,
                        event_id: format!("{command_id}:delivery"),
                        body: Some(proto::app_event::Body::GroupDeliveryChanged(
                            proto::GroupDeliveryChanged {
                                group_id: received.group_id().as_bytes().to_vec(),
                                message_id: encode_message_id(message_id.as_bytes()),
                                state: state as i32,
                                epoch: received.epoch(),
                                delivered_count: delivered,
                                intended_count: intended,
                            },
                        )),
                    },
                });
            }
        }
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        Ok(())
    }

    fn stage_future_group_message(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        stored: &proto::StoredGroup,
        ciphertext: &crate::GroupCiphertext,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let gap = ciphertext
            .epoch()
            .checked_sub(stored.epoch)
            .ok_or(Error::Serialization)?;
        let buffered_bytes: usize = candidate
            .buffered_group_messages
            .iter()
            .map(|message| message.ciphertext.len())
            .sum();
        let warning_code = if gap > MAX_FUTURE_EPOCHS as u64 {
            Some(1)
        } else if candidate.buffered_group_messages.len() >= MAX_PENDING_OUTBOUND_ENTRIES
            || buffered_bytes.saturating_add(inbound.payload.len()) > MAX_FUTURE_EPOCH_BUFFER_BYTES
        {
            Some(2)
        } else {
            None
        };
        if let Some(code) = warning_code {
            output.events.push(AppEvent {
                inner: proto::AppEvent {
                    version: PROTOCOL_VERSION,
                    event_id: format!("{command_id}:security-warning"),
                    body: Some(proto::app_event::Body::GroupSecurityWarning(
                        proto::GroupSecurityWarning {
                            group_id: ciphertext.group_id().as_bytes().to_vec(),
                            code,
                            evidence_id: Sha256::digest(&inbound.payload).to_vec(),
                            epoch: stored.epoch,
                        },
                    )),
                },
            });
            return Ok(());
        }
        candidate
            .buffered_group_messages
            .push(proto::BufferedGroupMessage {
                group_id: ciphertext.group_id().as_bytes().to_vec(),
                epoch: ciphertext.epoch(),
                message_id: ciphertext.message_id().as_bytes().to_vec(),
                ciphertext: inbound.payload.clone(),
            });
        let fetch = proto::GroupEpochFetch {
            version: PROTOCOL_VERSION,
            group_id: ciphertext.group_id().as_bytes().to_vec(),
            from_epoch: stored.epoch + 1,
            through_epoch: ciphertext.epoch(),
        };
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: format!("{command_id}:fetch-epochs"),
                kind: proto::OutboundKind::GroupCoordinator as i32,
                relay_url: stored.relay_url.clone(),
                destination: policy.coordination_id().to_vec(),
                payload: fetch.encode_to_vec(),
            },
        });
        Ok(())
    }

    fn stage_send_group_message(
        &self,
        command_id: &str,
        send: &proto::SendGroupMessage,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let group_id: [u8; 32] = send
            .group_id
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedBundle)?;
        let stored = candidate
            .groups
            .iter()
            .find(|group| group.group_id == send.group_id)
            .cloned()
            .ok_or(Error::InvalidKey)?;
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let mut mls_storage =
            TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
        let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
        let sender = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        let reply_to = if send.reply_to_message_id.is_empty() {
            None
        } else {
            Some(decode_message_id(&send.reply_to_message_id)?)
        };
        let ciphertext = engine.encrypt_application(
            &self.identity,
            &mut mls_storage,
            GroupApplication::text(send.body.clone(), reply_to, send.sender_timestamp_ms),
        )?;
        candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        let intended_identities = engine
            .policy()
            .members()
            .iter()
            .filter(|identity| **identity != sender)
            .map(|identity| identity.to_vec())
            .collect::<Vec<_>>();
        if candidate.delivery_ledgers.len() >= MAX_PENDING_OUTBOUND_ENTRIES {
            let expired = candidate.delivery_ledgers.remove(0);
            output.events.push(AppEvent {
                inner: proto::AppEvent {
                    version: PROTOCOL_VERSION,
                    event_id: format!("{command_id}:expired"),
                    body: Some(proto::app_event::Body::GroupDeliveryChanged(
                        proto::GroupDeliveryChanged {
                            group_id: expired.group_id,
                            message_id: encode_message_id(
                                &expired
                                    .message_id
                                    .as_slice()
                                    .try_into()
                                    .map_err(|_| Error::Serialization)?,
                            ),
                            state: proto::GroupDeliveryState::Expired as i32,
                            epoch: expired.epoch,
                            delivered_count: u32::try_from(expired.acknowledged_identities.len())
                                .map_err(|_| Error::Serialization)?,
                            intended_count: u32::try_from(expired.intended_identities.len())
                                .map_err(|_| Error::Serialization)?,
                        },
                    )),
                },
            });
        }
        candidate
            .delivery_ledgers
            .push(proto::StoredDeliveryLedger {
                group_id: group_id.to_vec(),
                message_id: ciphertext.message_id().as_bytes().to_vec(),
                epoch: ciphertext.epoch(),
                original_sender_identity: sender.to_vec(),
                intended_identities: intended_identities.clone(),
                acknowledged_identities: Vec::new(),
                sent: false,
                terminal_state: proto::GroupDeliveryState::Unspecified as i32,
            });
        let message_id = encode_message_id(ciphertext.message_id().as_bytes());
        output.events.push(AppEvent {
            inner: proto::AppEvent {
                version: PROTOCOL_VERSION,
                event_id: format!("{command_id}:sending"),
                body: Some(proto::app_event::Body::GroupDeliveryChanged(
                    proto::GroupDeliveryChanged {
                        group_id: group_id.to_vec(),
                        message_id,
                        state: proto::GroupDeliveryState::Sending as i32,
                        epoch: ciphertext.epoch(),
                        delivered_count: 0,
                        intended_count: u32::try_from(intended_identities.len())
                            .map_err(|_| Error::Serialization)?,
                    },
                )),
            },
        });
        output.outbound.push(OutboundItem {
            inner: proto::OutboundItem {
                item_id: command_id.to_owned(),
                kind: proto::OutboundKind::GroupMessage as i32,
                relay_url: stored.relay_url,
                destination: engine.policy().coordination_id().to_vec(),
                payload: ciphertext.encode(),
            },
        });
        Ok(())
    }
}

fn encode_message_id(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_message_id(encoded: &str) -> Result<crate::GroupMessageId, Error> {
    if encoded.len() != 32 {
        return Err(Error::MalformedBundle);
    }
    let mut bytes = [0_u8; 16];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(crate::GroupMessageId::from_bytes(bytes))
}

fn hex_nibble(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::MalformedBundle),
    }
}

fn stored_group(engine: &GroupEngine) -> proto::StoredGroup {
    let policy = engine.policy();
    proto::StoredGroup {
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
    }
}

fn apply_delivery_acknowledgement(
    candidate: &mut proto::ClientCheckpoint,
    group_id: GroupId,
    authenticated_sender: [u8; 32],
    original_sender: [u8; 32],
    message_id: crate::GroupMessageId,
) -> Result<Option<(proto::GroupDeliveryState, u32, u32)>, Error> {
    let ledger = candidate
        .delivery_ledgers
        .iter_mut()
        .find(|ledger| {
            ledger.group_id.as_slice() == group_id.as_bytes()
                && ledger.message_id.as_slice() == message_id.as_bytes()
        })
        .ok_or(Error::InvalidKey)?;
    if ledger.original_sender_identity.as_slice() != original_sender
        || !ledger
            .intended_identities
            .iter()
            .any(|identity| identity.as_slice() == authenticated_sender)
        || ledger.terminal_state != proto::GroupDeliveryState::Unspecified as i32
    {
        return Err(Error::InvalidSignature);
    }
    if ledger
        .acknowledged_identities
        .iter()
        .any(|identity| identity.as_slice() == authenticated_sender)
    {
        return Ok(None);
    }
    ledger
        .acknowledged_identities
        .push(authenticated_sender.to_vec());
    let delivered =
        u32::try_from(ledger.acknowledged_identities.len()).map_err(|_| Error::Serialization)?;
    let intended =
        u32::try_from(ledger.intended_identities.len()).map_err(|_| Error::Serialization)?;
    let state = if delivered == intended {
        proto::GroupDeliveryState::Delivered
    } else {
        proto::GroupDeliveryState::DeliveredTo
    };
    Ok(Some((state, delivered, intended)))
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
