impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_migrate_legacy_pairwise_state(
        &self,
        migration: &proto::MigrateLegacyPairwiseState,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<(), Error> {
        if !candidate.pairwise_account_state.is_empty()
            || !candidate.pairwise_fallback_key.is_empty()
            || !candidate.pairwise_sessions.is_empty()
        {
            return Err(Error::InvalidSignature);
        }
        let fallback_key: [u8; 32] = migration
            .fallback_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let account = PlatformAccount::import(&migration.account_state, fallback_key)?;
        // Force root binding and serialization before mutating the candidate.
        account.signed_prekey_bundle(&self.identity)?.verify()?;
        let account_state = account.export_state()?;

        let local_identity = self
            .identity
            .ensure_public_key(crate::IdentityPurpose::Root)?;
        let mut seen = std::collections::HashSet::new();
        let sessions = migration
            .sessions
            .iter()
            .map(|legacy| {
                let remote_identity: [u8; 32] = legacy
                    .remote_identity
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?;
                if remote_identity == local_identity || !seen.insert(remote_identity) {
                    return Err(Error::InvalidKey);
                }
                let session = PlatformSession::import(&legacy.state, remote_identity)?;
                Ok(proto::StoredPairwiseSession {
                    remote_identity: remote_identity.to_vec(),
                    state: session.export()?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        candidate.pairwise_account_state = account_state;
        candidate.pairwise_fallback_key = fallback_key.to_vec();
        candidate.pairwise_sessions = sessions;
        Ok(())
    }

    pub(super) fn stage_register_pairwise_contact(
        &self,
        register: &proto::RegisterPairwiseContact,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<(), Error> {
        let bundle = PrekeyBundle::decode(&register.prekey_bundle)?;
        bundle.verify()?;
        let local_identity = self
            .identity
            .ensure_public_key(crate::IdentityPurpose::Root)?;
        if bundle.identity.identity_key == local_identity {
            return Err(Error::InvalidKey);
        }
        let stored = proto::StoredPairwiseContact {
            identity: bundle.identity.identity_key.to_vec(),
            prekey_bundle: register.prekey_bundle.clone(),
            relay_url: register.relay_url.clone(),
            relationship: register.relationship,
            introduction_received: false,
            introduction_sent: false,
        };
        if let Some(existing) = candidate
            .pairwise_contacts
            .iter_mut()
            .find(|existing| existing.identity.as_slice() == bundle.identity.identity_key)
        {
            existing.prekey_bundle = stored.prekey_bundle;
            existing.relay_url = stored.relay_url;
            if existing.relationship == proto::PairwiseRelationship::Unspecified as i32 {
                existing.relationship = stored.relationship;
            }
        } else {
            candidate.pairwise_contacts.push(stored);
        }
        Ok(())
    }

    pub(super) fn stage_set_pairwise_relationship(
        &self,
        set: &proto::SetPairwiseRelationship,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<(), Error> {
        let contact = candidate
            .pairwise_contacts
            .iter_mut()
            .find(|contact| contact.identity == set.identity)
            .ok_or(Error::InvalidKey)?;
        let current = pairwise_relationship(contact)?;
        let next = proto::PairwiseRelationship::try_from(set.relationship)
            .map_err(|_| Error::MalformedBundle)?;
        let permitted = matches!(
            (current, next),
            (current, next) if current == next
        ) || matches!(
            (current, next),
            (
                proto::PairwiseRelationship::IncomingRequest,
                proto::PairwiseRelationship::Contact
            ) | (
                proto::PairwiseRelationship::Contact,
                proto::PairwiseRelationship::OutgoingRequest
            )
        );
        if !permitted {
            return Err(Error::InvalidSignature);
        }
        contact.relationship = next as i32;
        contact.introduction_received = false;
        contact.introduction_sent = false;
        Ok(())
    }

    pub(super) fn stage_remove_pairwise_contact(
        &self,
        remove: &proto::RemovePairwiseContact,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<(), Error> {
        let previous_count = candidate.pairwise_contacts.len();
        candidate
            .pairwise_contacts
            .retain(|contact| contact.identity != remove.identity);
        if candidate.pairwise_contacts.len() == previous_count {
            return Err(Error::InvalidKey);
        }
        candidate
            .pairwise_sessions
            .retain(|session| session.remote_identity != remove.identity);
        candidate
            .pending_outbound
            .retain(|item| item.destination != remove.identity);
        Ok(())
    }

    pub(super) fn stage_send_pairwise_control(
        &self,
        command_id: &str,
        send: &proto::SendPairwiseControl,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let recipient: [u8; 32] = send
            .recipient_identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let item = self.stage_pairwise_item(
            command_id,
            recipient,
            send.content_kind,
            send.payload.clone(),
            candidate,
        )?;
        output.outbound.push(OutboundItem { inner: item });
        Ok(())
    }

    pub(super) fn stage_send_direct_application(
        &self,
        send: &proto::SendDirectApplication,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<proto::OutboundItem, Error> {
        let recipient: [u8; 32] = send
            .recipient_identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let application = send.application.clone().ok_or(Error::MalformedBundle)?;
        let contact_index = candidate
            .pairwise_contacts
            .iter()
            .position(|contact| contact.identity.as_slice() == recipient)
            .ok_or(Error::InvalidKey)?;
        let contact = &candidate.pairwise_contacts[contact_index];
        let relationship = pairwise_relationship(contact)?;
        let is_acknowledgement = matches!(
            application.body.as_ref(),
            Some(proto::direct_application::Body::Acknowledgement(_))
        );
        match relationship {
            proto::PairwiseRelationship::Contact => {
                if !send.sender_contact_card.is_empty() {
                    return Err(Error::InvalidSignature);
                }
            }
            proto::PairwiseRelationship::OutgoingRequest => {
                if send.sender_contact_card.is_empty()
                    || contact.introduction_sent
                    || !matches!(
                        application.body.as_ref(),
                        Some(proto::direct_application::Body::Message(_))
                    )
                {
                    return Err(Error::InvalidSignature);
                }
            }
            proto::PairwiseRelationship::IncomingRequest => {
                if !is_acknowledgement || !send.sender_contact_card.is_empty() {
                    return Err(Error::InvalidSignature);
                }
            }
            proto::PairwiseRelationship::Unspecified => unreachable!(),
        }
        let item_id = application.application_id.clone();
        let item = self.stage_pairwise_payload(
            &item_id,
            recipient,
            proto::pairwise_payload::Body::DirectApplication(application),
            send.local_only,
            send.sender_contact_card.clone(),
            candidate,
        )?;
        if relationship == proto::PairwiseRelationship::OutgoingRequest {
            candidate.pairwise_contacts[contact_index].introduction_sent = true;
        }
        Ok(item)
    }

    pub(super) fn stage_wrap_addressed_controls(
        &self,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let pending = std::mem::take(&mut candidate.pending_outbound);
        candidate.pending_outbound = pending
            .into_iter()
            .map(|item| self.wrap_addressed_control(item, candidate))
            .collect::<Result<Vec<_>, _>>()?;

        let released = std::mem::take(&mut output.outbound);
        for item in released {
            let inner = self.wrap_addressed_control(item.inner, candidate)?;
            if is_addressed_group_control(inner.kind) {
                candidate.pending_outbound.push(inner);
            } else {
                output.outbound.push(OutboundItem { inner });
            }
        }
        Ok(())
    }

    fn wrap_addressed_control(
        &self,
        item: proto::OutboundItem,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<proto::OutboundItem, Error> {
        if !is_addressed_group_control(item.kind) {
            return Ok(item);
        }
        let Ok(recipient) = item.destination.as_slice().try_into() else {
            return Ok(item);
        };
        if !candidate
            .pairwise_contacts
            .iter()
            .any(|contact| contact.identity.as_slice() == recipient)
        {
            return Ok(item);
        }
        self.stage_pairwise_item(&item.item_id, recipient, item.kind, item.payload, candidate)
    }

    pub(super) fn stage_pairwise_item(
        &self,
        item_id: &str,
        recipient: [u8; 32],
        content_kind: i32,
        payload: Vec<u8>,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<proto::OutboundItem, Error> {
        self.stage_pairwise_payload(
            item_id,
            recipient,
            proto::pairwise_payload::Body::GroupControl(proto::PairwiseGroupControl {
                content_kind: content_kind
                    .try_into()
                    .map_err(|_| Error::MalformedBundle)?,
                payload,
            }),
            false,
            Vec::new(),
            candidate,
        )
    }

    pub(super) fn stage_pairwise_payload(
        &self,
        item_id: &str,
        recipient: [u8; 32],
        body: proto::pairwise_payload::Body,
        local_only: bool,
        sender_contact_card: Vec<u8>,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<proto::OutboundItem, Error> {
        let contact = candidate
            .pairwise_contacts
            .iter()
            .find(|contact| contact.identity.as_slice() == recipient)
            .ok_or(Error::InvalidKey)?
            .clone();
        let local_identity = self
            .identity
            .ensure_public_key(crate::IdentityPurpose::Root)?;
        let plaintext = proto::PairwisePayload {
            version: crate::wire::PAIRWISE_PAYLOAD_VERSION,
            sender_identity: local_identity.to_vec(),
            recipient_identity: recipient.to_vec(),
            body: Some(body),
        }
        .encode_to_vec();

        let body = if let Some(index) = preferred_session_index(candidate, recipient)? {
            let stored = &mut candidate.pairwise_sessions[index];
            let mut session = PlatformSession::import(&stored.state, recipient)?;
            let message = session.encrypt(&plaintext)?;
            stored.state = session.export()?;
            proto::pairwise_envelope::Body::Message(encode_olm_message(&message))
        } else {
            let account = pairwise_account(candidate)?.ok_or(Error::InvalidKey)?;
            let bundle = PrekeyBundle::decode(&contact.prekey_bundle)?;
            let (session, initiation) =
                PlatformSession::establish_outbound(&account, &self.identity, &bundle, &plaintext)?;
            candidate
                .pairwise_sessions
                .push(proto::StoredPairwiseSession {
                    remote_identity: recipient.to_vec(),
                    state: session.export()?,
                });
            proto::pairwise_envelope::Body::Initiation(Initiation::encode(&initiation))
        };

        Ok(proto::OutboundItem {
            item_id: item_id.to_owned(),
            kind: proto::OutboundKind::Pairwise as i32,
            relay_url: contact.relay_url,
            destination: recipient.to_vec(),
            payload: proto::PairwiseEnvelope {
                version: PROTOCOL_VERSION,
                sender_identity: local_identity.to_vec(),
                recipient_identity: recipient.to_vec(),
                sender_contact_card,
                body: Some(body),
            }
            .encode_to_vec(),
            local_only,
        })
    }

}
