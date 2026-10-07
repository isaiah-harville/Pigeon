impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_replay_buffered_group_messages(
        &self,
        command_id: &str,
        group_id: &[u8],
        epoch: u64,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let mut index = 0;
        let mut replayed = 0;
        while index < candidate.buffered_group_messages.len() {
            let buffered = &candidate.buffered_group_messages[index];
            if buffered.group_id != group_id || buffered.epoch > epoch {
                index += 1;
                continue;
            }
            let buffered = candidate.buffered_group_messages.remove(index);
            let before = candidate.clone();
            let before_output = output.clone();
            let inbound = proto::ApplyInbound {
                kind: proto::OutboundKind::GroupMessage as i32,
                payload: buffered.ciphertext.clone(),
                request_id: String::new(),
                now_ms: 0,
            };
            if let Err(error) = self.stage_apply_group_message(
                &format!("{command_id}:buffered:{replayed}"),
                &inbound,
                candidate,
                output,
            ) {
                if !super::is_rejected_sequenced_input(&error) {
                    return Err(error);
                }
                *candidate = before;
                *output = before_output;
                replayed += 1;
                continue;
            }
            if candidate.pending_events.len() + output.events.len() > MAX_PENDING_OUTBOUND_ENTRIES
                || candidate.pending_outbound.len() + output.outbound.len()
                    > MAX_PENDING_OUTBOUND_ENTRIES
            {
                *candidate = before;
                *output = before_output;
                candidate.buffered_group_messages.insert(index, buffered);
                break;
            }
            replayed += 1;
        }
        Ok(())
    }

    pub(super) fn stage_apply_group_message(
        &self,
        command_id: &str,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let ciphertext = crate::GroupCiphertext::decode(&inbound.payload)?;
        let ciphertext_hash = Sha256::digest(&inbound.payload);
        if candidate.processed_group_messages.iter().any(|processed| {
            processed.group_id.as_slice() == ciphertext.group_id().as_bytes()
                && processed.ciphertext_hash.as_slice() == ciphertext_hash.as_slice()
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
                    && buffered.ciphertext == inbound.payload
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
        let mut engine = GroupEngine::restore(&mls_storage, policy.clone(), stored.epoch)?;
        let received = engine.decrypt_application(&mut mls_storage, &ciphertext)?;
        if candidate.processed_group_messages.iter().any(|processed| {
            processed.group_id.as_slice() == received.group_id().as_bytes()
                && processed.message_id.as_slice() == received.message_id().as_bytes()
                && processed.sender_identity.as_slice() == received.sender_identity()
        }) {
            candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
            return Ok(());
        }
        if candidate.processed_group_messages.len() >= MAX_PENDING_OUTBOUND_ENTRIES {
            candidate.processed_group_messages.remove(0);
        }
        candidate
            .processed_group_messages
            .push(proto::ProcessedGroupMessage {
                group_id: ciphertext.group_id().as_bytes().to_vec(),
                message_id: ciphertext.message_id().as_bytes().to_vec(),
                sender_identity: received.sender_identity().to_vec(),
                ciphertext_hash: ciphertext_hash.to_vec(),
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
                // Receipts are queued and sent in batches (see
                // `stage_flush_group_acknowledgements`) so the group mailbox
                // does not grow by one entry per member for every message.
                if candidate.pending_group_acknowledgements.len() >= MAX_PENDING_OUTBOUND_ENTRIES {
                    candidate.pending_group_acknowledgements.remove(0);
                }
                candidate
                    .pending_group_acknowledgements
                    .push(proto::PendingGroupAcknowledgement {
                        group_id: received.group_id().as_bytes().to_vec(),
                        original_sender_identity: received.sender_identity().to_vec(),
                        message_id: received.message_id().as_bytes().to_vec(),
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
            GroupApplication::Acknowledgement { messages } => {
                // Every member receives every batch; only receipts for this
                // device's own messages matter here. Receipts for messages whose
                // ledger was evicted or already settled are ignored, so one
                // stale entry never rejects the rest of the batch.
                let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
                for (index, acknowledged) in messages.iter().enumerate() {
                    if acknowledged.original_sender != local_identity {
                        continue;
                    }
                    let Ok(Some((state, delivered, intended))) = apply_delivery_acknowledgement(
                        candidate,
                        received.group_id(),
                        received.sender_identity(),
                        acknowledged.original_sender,
                        acknowledged.message_id,
                    ) else {
                        continue;
                    };
                    output.events.push(AppEvent {
                        inner: proto::AppEvent {
                            version: PROTOCOL_VERSION,
                            event_id: format!("{command_id}:delivery:{index}"),
                            body: Some(proto::app_event::Body::GroupDeliveryChanged(
                                proto::GroupDeliveryChanged {
                                    group_id: received.group_id().as_bytes().to_vec(),
                                    message_id: encode_message_id(
                                        acknowledged.message_id.as_bytes(),
                                    ),
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
            GroupApplication::RecoveryControl {
                kind,
                recipient,
                payload,
            } => {
                let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
                candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
                if recipient.is_some_and(|recipient| recipient != local_identity) {
                    return Ok(());
                }
                let control = proto::ApplyInbound {
                    kind: proto::OutboundKind::Unspecified as i32,
                    payload: payload.clone(),
                    request_id: inbound.request_id.clone(),
                    now_ms: inbound.now_ms,
                };
                match kind {
                    RecoveryControlKind::Proposal => {
                        if !policy.can_endorse_recovery(local_identity) {
                            return Ok(());
                        }
                        self.stage_apply_group_recovery_proposal(
                            command_id,
                            received.group_id(),
                            &received.sender_identity(),
                            &control,
                            candidate,
                            output,
                        )?;
                    }
                    RecoveryControlKind::Endorsement => {
                        self.stage_apply_group_recovery_endorsement(
                            command_id,
                            received.group_id(),
                            &received.sender_identity(),
                            &control,
                            candidate,
                            output,
                        )?;
                    }
                    RecoveryControlKind::Candidate => {
                        self.stage_apply_group_coordinator(
                            command_id,
                            &proto::ApplyInbound {
                                kind: proto::OutboundKind::GroupCoordinator as i32,
                                ..control
                            },
                            candidate,
                            output,
                        )?;
                    }
                }
                return Ok(());
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
        if gap > MAX_FUTURE_EPOCHS as u64 {
            return Err(Error::ResourceLimit("future group epoch gap"));
        }
        let buffered_bytes: usize = candidate
            .buffered_group_messages
            .iter()
            .map(|message| message.ciphertext.len())
            .sum();
        let buffer_full = candidate.buffered_group_messages.len() >= MAX_BUFFERED_GROUP_MESSAGES
            || buffered_bytes.saturating_add(inbound.payload.len()) > MAX_FUTURE_EPOCH_BUFFER_BYTES;
        if buffer_full {
            return Err(Error::FutureEpochBufferFull);
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
                local_only: false,
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
                event_id: format!("{command_id}:local"),
                body: Some(proto::app_event::Body::GroupMessageReceived(
                    proto::GroupMessageReceived {
                        group_id: group_id.to_vec(),
                        message_id: message_id.clone(),
                        sender_identity: sender.to_vec(),
                        body: send.body.clone(),
                        reply_to_message_id: reply_to
                            .map(|id| encode_message_id(id.as_bytes()))
                            .unwrap_or_default(),
                        epoch: ciphertext.epoch(),
                    },
                )),
            },
        });
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
                local_only: false,
            },
        });
        Ok(())
    }

}
