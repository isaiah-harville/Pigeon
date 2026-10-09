impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    /// Encrypts queued delivery receipts as batched acknowledgements for
    /// `only_group`, or for every group. Receipts for groups this device has
    /// left, or that were dissolved, are dropped: nobody can read them.
    pub(super) fn stage_flush_group_acknowledgements(
        &self,
        command_id: &str,
        only_group: Option<&[u8]>,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let mut group_ids: Vec<Vec<u8>> = Vec::new();
        for pending in &candidate.pending_group_acknowledgements {
            if only_group.is_none_or(|group| group == pending.group_id.as_slice())
                && !group_ids.contains(&pending.group_id)
            {
                group_ids.push(pending.group_id.clone());
            }
        }
        let local_identity = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        for (group_index, group_id) in group_ids.iter().enumerate() {
            let mut messages = Vec::new();
            let mut retained = Vec::new();
            for pending in candidate.pending_group_acknowledgements.drain(..) {
                if &pending.group_id != group_id {
                    retained.push(pending);
                    continue;
                }
                messages.push(AcknowledgedMessage {
                    original_sender: pending
                        .original_sender_identity
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Serialization)?,
                    message_id: GroupMessageId::from_bytes(
                        pending
                            .message_id
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::Serialization)?,
                    ),
                });
            }
            candidate.pending_group_acknowledgements = retained;

            let Some(stored) = candidate
                .groups
                .iter()
                .find(|stored| &stored.group_id == group_id)
                .cloned()
            else {
                continue;
            };
            let policy = PigeonGroupPolicy::decode(&stored.policy)?;
            if policy.dissolved() || !policy.members().contains(&local_identity) {
                continue;
            }
            let mut mls_storage =
                TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?;
            let mut engine = GroupEngine::restore(&mls_storage, policy, stored.epoch)?;
            for (batch_index, batch) in messages.chunks(MAX_GROUP_ACKNOWLEDGEMENT_BATCH).enumerate()
            {
                let ciphertext = engine.encrypt_application(
                    &self.identity,
                    &mut mls_storage,
                    GroupApplication::acknowledgements(batch.to_vec())?,
                )?;
                output.outbound.push(OutboundItem {
                    inner: proto::OutboundItem {
                        item_id: format!("{command_id}:ack:{group_index}:{batch_index}"),
                        kind: proto::OutboundKind::GroupMessage as i32,
                        relay_url: stored.relay_url.clone(),
                        destination: engine.policy().coordination_id().to_vec(),
                        payload: ciphertext.encode(),
                        local_only: false,
                    },
                });
            }
            candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
        }
        Ok(())
    }

    /// Flushes any group whose queue holds a full batch, so a burst of
    /// messages is acknowledged without waiting for the host's throttle.
    pub(super) fn stage_flush_full_acknowledgement_batches(
        &self,
        command_id: &str,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let mut full = Vec::new();
        for pending in &candidate.pending_group_acknowledgements {
            if !full.contains(&pending.group_id)
                && candidate
                    .pending_group_acknowledgements
                    .iter()
                    .filter(|other| other.group_id == pending.group_id)
                    .count()
                    >= MAX_GROUP_ACKNOWLEDGEMENT_BATCH
            {
                full.push(pending.group_id.clone());
            }
        }
        for group_id in full {
            self.stage_flush_group_acknowledgements(
                command_id,
                Some(group_id.as_slice()),
                candidate,
                output,
            )?;
        }
        Ok(())
    }
}
