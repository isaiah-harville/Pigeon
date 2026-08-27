use prost::Message;
use sha2::{Digest, Sha256};

use super::PigeonClient;
use super::checkpoint::{apply_delivery_acknowledgement, decode_message_id, encode_message_id};

use crate::Error;
use crate::client::{AppEvent, ClientOutput, OutboundItem};
use crate::group::{GroupApplication, GroupEngine, PigeonGroupPolicy};
use crate::identity::{IdentityPurpose, SecureIdentity};
use crate::storage::{StateStore, TransactionalOpenMlsStorage};
use crate::wire::{
    MAX_FUTURE_EPOCH_BUFFER_BYTES, MAX_FUTURE_EPOCHS, MAX_PENDING_OUTBOUND_ENTRIES,
    PROTOCOL_VERSION, proto,
};

impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_apply_group_message(
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

    pub(super) fn stage_send_group_message(
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
