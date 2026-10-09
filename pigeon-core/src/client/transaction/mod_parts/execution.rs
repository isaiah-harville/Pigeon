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
                deferred_events: Vec::new(),
                pending_group_recoveries: Vec::new(),
                pending_group_acknowledgements: Vec::new(),
                pending_group_leaves: Vec::new(),
                group_invites: Vec::new(),
                group_invite_joins: Vec::new(),
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
            proto::client_command::Body::CreateGroupInvite(value) => {
                self.stage_create_group_invite(value, &mut candidate)?
            }
            proto::client_command::Body::RevokeGroupInvite(value) => {
                self.stage_revoke_group_invite(value, &mut candidate)?
            }
            proto::client_command::Body::StartGroupInviteJoin(value) => self
                .stage_start_group_invite_join(
                    &command.inner.command_id,
                    value,
                    &mut candidate,
                    &mut output,
                )?,
            proto::client_command::Body::ApplyGroupInviteInboxEnvelope(value) => {
                let pristine = candidate.clone();
                match self.stage_apply_group_invite_inbox_envelope(
                    &command.inner.command_id,
                    value,
                    &mut candidate,
                    &mut output,
                ) {
                    Ok(()) => output.invite_envelope_outcome = GroupInviteEnvelopeOutcome::Accepted,
                    Err(error) if is_rejected_invite_envelope(&error) => {
                        candidate = pristine;
                        output = ClientOutput::empty(candidate.generation + 1);
                        output.invite_envelope_outcome = GroupInviteEnvelopeOutcome::Rejected;
                    }
                    Err(error) => return Err(error),
                }
            }
            proto::client_command::Body::DecideGroupInviteRequest(value) => self
                .stage_decide_group_invite_request(
                    &command.inner.command_id,
                    value,
                    &mut candidate,
                    &mut output,
                )?,
            proto::client_command::Body::ApplyGroupInviteReply(value) => {
                let pristine = candidate.clone();
                match self.stage_apply_group_invite_reply(
                    &command.inner.command_id,
                    value,
                    &mut candidate,
                    &mut output,
                ) {
                    Ok(()) => output.invite_envelope_outcome = GroupInviteEnvelopeOutcome::Accepted,
                    Err(error) if is_rejected_invite_envelope(&error) => {
                        candidate = pristine;
                        output = ClientOutput::empty(candidate.generation + 1);
                        output.invite_envelope_outcome = GroupInviteEnvelopeOutcome::Rejected;
                    }
                    Err(error) => return Err(error),
                }
            }
            proto::client_command::Body::RefreshGroupInvites(value) => {
                if !self.stage_refresh_group_invites(value.now_ms, &mut candidate)? {
                    return Ok(ClientOutput::empty(self.state.generation));
                }
            }
            proto::client_command::Body::CreateGroup(create) => {
                self.stage_create_group(
                    &command.inner.command_id,
                    create,
                    &mut candidate,
                    &mut output,
                )?;
            }
            proto::client_command::Body::ApplyInbound(inbound) => {
                let inbound_kind = proto::OutboundKind::try_from(inbound.kind).ok();
                if inbound_kind == Some(proto::OutboundKind::GroupMessage) {
                    output.group_message_outcome = GroupMessageOutcome::Accepted;
                }
                let pristine = candidate.clone();
                if let Err(error) = self.stage_apply_inbound(
                    &command.inner.command_id,
                    inbound,
                    &mut candidate,
                    &mut output,
                ) {
                    if is_rejected_sequenced_input(&error)
                        && inbound_kind == Some(proto::OutboundKind::GroupCoordinator)
                    {
                        candidate = pristine;
                        output = ClientOutput::empty(candidate.generation + 1);
                        if !self.stage_consume_rejected_group_coordinator(
                            &command.inner.command_id,
                            inbound,
                            &mut candidate,
                            &mut output,
                        )? {
                            return Err(error);
                        }
                    } else if is_rejected_sequenced_input(&error)
                        && inbound_kind == Some(proto::OutboundKind::GroupMessage)
                    {
                        // The relay sequence is durable only after this empty
                        // classification transaction lands. Cryptographic and
                        // policy state remain exactly as they were.
                        candidate = pristine;
                        output = ClientOutput::empty(candidate.generation + 1);
                        output.group_message_outcome = GroupMessageOutcome::Rejected;
                    } else {
                        return Err(error);
                    }
                }
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
                let mut released_events = Vec::new();
                candidate.deferred_events.retain(|deferred| {
                    if acknowledgement
                        .outbound_item_ids
                        .iter()
                        .any(|id| id == &deferred.outbound_item_id)
                    {
                        if let Some(event) = deferred.event.clone() {
                            released_events.push(event);
                        }
                        false
                    } else {
                        true
                    }
                });
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
                output.events.extend(
                    released_events
                        .into_iter()
                        .map(|inner| crate::client::AppEvent { inner }),
                );
            }
            proto::client_command::Body::ConfirmGroupRelayAuthorization(confirmation) => {
                let stored = candidate
                    .groups
                    .iter()
                    .find(|stored| stored.group_id == confirmation.group_id)
                    .ok_or(Error::InvalidKey)?;
                let policy = PigeonGroupPolicy::decode(&stored.policy)?;
                let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
                let capability_public_key = policy
                    .member_capability_key(local_identity)
                    .ok_or(Error::InvalidKey)?;
                let current_capability_id = relay_capability_id(
                    *policy.group_id().as_bytes(),
                    policy.coordination_id(),
                    stored.epoch,
                    policy.revision(),
                    policy.roster_hash(),
                    capability_public_key,
                );
                if confirmation.capability_id.as_slice() != current_capability_id {
                    return Err(Error::InvalidSignature);
                }
                let mut released_events = Vec::new();
                candidate.deferred_events.retain(|deferred| {
                    if deferred.group_id == confirmation.group_id
                        && !deferred.release_capability_id.is_empty()
                    {
                        if let Some(event) = deferred.event.clone() {
                            released_events.push(event);
                        }
                        false
                    } else {
                        true
                    }
                });
                output.events.extend(
                    released_events
                        .into_iter()
                        .map(|inner| crate::client::AppEvent { inner }),
                );
            }
            proto::client_command::Body::RecoverGroup(recovery) => {
                self.stage_recover_group(
                    &command.inner.command_id,
                    recovery,
                    &mut candidate,
                    &mut output,
                )?;
            }
            proto::client_command::Body::FlushGroupAcknowledgements(flush) => {
                // Hosts flush on timers and at unlock; with nothing queued the
                // command commits nothing, so idle timers cost no checkpoint write.
                if !candidate
                    .pending_group_acknowledgements
                    .iter()
                    .any(|pending| flush.group_id.is_empty() || pending.group_id == flush.group_id)
                {
                    return Ok(ClientOutput::empty(self.state.generation));
                }
                self.stage_flush_group_acknowledgements(
                    &command.inner.command_id,
                    (!flush.group_id.is_empty()).then_some(flush.group_id.as_slice()),
                    &mut candidate,
                    &mut output,
                )?;
            }
            proto::client_command::Body::BeginGroupRecovery(recovery) => {
                self.stage_begin_group_recovery(
                    &command.inner.command_id,
                    recovery,
                    &mut candidate,
                    &mut output,
                )?;
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
            proto::client_command::Body::MigrateLegacyPairwiseState(migration) => {
                self.stage_migrate_legacy_pairwise_state(migration, &mut candidate)?;
            }
            proto::client_command::Body::RegisterPairwiseContact(register) => {
                self.stage_register_pairwise_contact(register, &mut candidate)?;
            }
            proto::client_command::Body::SetPairwiseRelationship(set) => {
                self.stage_set_pairwise_relationship(set, &mut candidate)?;
            }
            proto::client_command::Body::RemovePairwiseContact(remove) => {
                self.stage_remove_pairwise_contact(remove, &mut candidate)?;
            }
            proto::client_command::Body::SendDirectApplication(send) => {
                let item = self.stage_send_direct_application(send, &mut candidate)?;
                output
                    .outbound
                    .push(crate::client::OutboundItem { inner: item });
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

        if let Some(proto::client_command::Body::ApplyInbound(inbound)) =
            command.inner.body.as_ref()
            && inbound.kind == proto::OutboundKind::GroupCoordinator as i32
            && inbound.now_ms > 0
        {
            self.stage_flush_public_group_invites(
                &command.inner.command_id,
                inbound.now_ms,
                &mut candidate,
                &mut output,
            )?;
        }

        let ready_groups: Vec<_> = candidate
            .groups
            .iter()
            .map(|group| (group.group_id.clone(), group.epoch))
            .collect();
        for (group_id, epoch) in ready_groups {
            self.stage_replay_buffered_group_messages(
                &command.inner.command_id,
                &group_id,
                epoch,
                &mut candidate,
                &mut output,
            )?;
        }

        self.stage_flush_full_acknowledgement_batches(
            &command.inner.command_id,
            &mut candidate,
            &mut output,
        )?;
        self.stage_wrap_addressed_controls(&mut candidate, &mut output)?;

        if candidate.pending_outbound.len() + output.outbound.len()
            > crate::MAX_PENDING_OUTBOUND_ENTRIES
            || candidate.pending_events.len() + output.events.len()
                > crate::MAX_PENDING_OUTBOUND_ENTRIES
            || candidate.deferred_events.len() > crate::MAX_PENDING_OUTBOUND_ENTRIES
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
            .chain(
                candidate
                    .deferred_events
                    .iter()
                    .map(prost::Message::encoded_len),
            )
            .sum::<usize>();
        if pending_effect_bytes > crate::wire::MAX_PENDING_EFFECT_BYTES {
            return Err(Error::ResourceLimit("pending core effect bytes"));
        }

        candidate.generation += 1;
        if candidate.applied_command_ids.len() >= crate::MAX_PENDING_OUTBOUND_ENTRIES {
            candidate.applied_command_ids.remove(0);
        }
        candidate
            .applied_command_ids
            .push(command.inner.command_id.clone());
        let checkpoint = encode_checkpoint(&candidate);
        self.store.replace(self.state.generation, checkpoint)?;

        self.state = candidate;
        Ok(output)
    }

}
