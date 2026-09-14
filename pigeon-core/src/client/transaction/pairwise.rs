use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;

use super::{PigeonClient, pairwise_account};
use crate::client::{ClientOutput, OutboundItem};
use crate::identity::{
    IdentityBundle, Initiation, PlatformAccount, PlatformSession, PrekeyBundle, decode_olm_message,
    encode_olm_message,
};
use crate::storage::StateStore;
use crate::wire::{PROTOCOL_VERSION, proto};
use crate::{Error, SecureIdentity};

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
        output.outbound = released
            .into_iter()
            .map(|item| {
                self.wrap_addressed_control(item.inner, candidate)
                    .map(|inner| OutboundItem { inner })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }

    fn wrap_addressed_control(
        &self,
        item: proto::OutboundItem,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<proto::OutboundItem, Error> {
        let Ok(kind) = proto::OutboundKind::try_from(item.kind) else {
            return Ok(item);
        };
        if !matches!(
            kind,
            proto::OutboundKind::GroupJoinRequest
                | proto::OutboundKind::GroupJoinMaterial
                | proto::OutboundKind::GroupWelcome
        ) {
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

    fn stage_pairwise_item(
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

        let body = if let Some(stored) = candidate
            .pairwise_sessions
            .iter_mut()
            .find(|session| session.remote_identity.as_slice() == recipient)
        {
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

    pub(super) fn stage_apply_pairwise_control(
        &self,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<(proto::PairwisePayload, Vec<u8>, bool), Error> {
        let envelope = proto::PairwiseEnvelope::decode(inbound.payload.as_slice())
            .map_err(|_| Error::MalformedBundle)?;
        if envelope.version != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "pairwise envelope",
                version: envelope.version,
            });
        }
        let sender: [u8; 32] = envelope
            .sender_identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let recipient: [u8; 32] = envelope
            .recipient_identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let local_identity = self
            .identity
            .ensure_public_key(crate::IdentityPurpose::Root)?;
        if recipient != local_identity {
            return Err(Error::InvalidSignature);
        }
        let sender_contact_card = envelope.sender_contact_card;
        let plaintext = match envelope.body.ok_or(Error::MalformedBundle)? {
            proto::pairwise_envelope::Body::Initiation(bytes) => {
                if candidate
                    .pairwise_sessions
                    .iter()
                    .any(|session| session.remote_identity.as_slice() == sender)
                {
                    return Err(Error::InvalidSignature);
                }
                let initiation = Initiation::decode(&bytes)?;
                if !candidate
                    .pairwise_contacts
                    .iter()
                    .any(|contact| contact.identity.as_slice() == sender)
                {
                    let incoming = verified_incoming_contact(
                        &sender_contact_card,
                        sender,
                        &initiation.identity,
                    )?;
                    let incoming_count = candidate
                        .pairwise_contacts
                        .iter()
                        .filter(|contact| {
                            matches!(
                                pairwise_relationship(contact),
                                Ok(proto::PairwiseRelationship::IncomingRequest)
                            )
                        })
                        .count();
                    if incoming_count >= crate::wire::MAX_INCOMING_MESSAGE_REQUESTS {
                        return Err(Error::ResourceLimit("incoming message requests"));
                    }
                    candidate.pairwise_contacts.push(incoming);
                } else if !sender_contact_card.is_empty() {
                    return Err(Error::InvalidSignature);
                }
                let contact = candidate
                    .pairwise_contacts
                    .iter()
                    .find(|contact| contact.identity.as_slice() == sender)
                    .ok_or(Error::InvalidSignature)?;
                let registered = PrekeyBundle::decode(&contact.prekey_bundle)?;
                if initiation.identity.identity_key != sender
                    || initiation.identity.curve_identity_key
                        != registered.identity.curve_identity_key
                {
                    return Err(Error::InvalidSignature);
                }
                let mut account = pairwise_account(candidate)?.ok_or(Error::InvalidKey)?;
                let (session, plaintext) = PlatformSession::establish_inbound(
                    &mut account,
                    &initiation.identity,
                    &initiation.message,
                )?;
                candidate.pairwise_account_state = account.export_state()?;
                candidate.pairwise_fallback_key = account.export_fallback_key().to_vec();
                candidate
                    .pairwise_sessions
                    .push(proto::StoredPairwiseSession {
                        remote_identity: sender.to_vec(),
                        state: session.export()?,
                    });
                plaintext
            }
            proto::pairwise_envelope::Body::Message(bytes) => {
                if !sender_contact_card.is_empty() {
                    return Err(Error::InvalidSignature);
                }
                let stored = candidate
                    .pairwise_sessions
                    .iter_mut()
                    .find(|session| session.remote_identity.as_slice() == sender)
                    .ok_or(Error::InvalidKey)?;
                let mut session = PlatformSession::import(&stored.state, sender)?;
                if session.remote_identity_key() != sender {
                    return Err(Error::InvalidSignature);
                }
                let plaintext = session.decrypt(&decode_olm_message(&bytes)?)?;
                stored.state = session.export()?;
                plaintext
            }
        };
        let control = proto::PairwisePayload::decode(plaintext.as_slice())
            .map_err(|_| Error::MalformedBundle)?;
        if control.version != crate::wire::PAIRWISE_PAYLOAD_VERSION
            || control.sender_identity.as_slice() != sender
            || control.recipient_identity.as_slice() != recipient
        {
            return Err(Error::InvalidSignature);
        }
        let contact_index = candidate
            .pairwise_contacts
            .iter()
            .position(|contact| contact.identity.as_slice() == sender)
            .ok_or(Error::InvalidSignature)?;
        let relationship = pairwise_relationship(&candidate.pairwise_contacts[contact_index])?;
        let mut suppress_direct_event = false;
        match (&control.body, relationship) {
            (
                Some(proto::pairwise_payload::Body::DirectApplication(application)),
                proto::PairwiseRelationship::IncomingRequest,
            ) => {
                let is_message = matches!(
                    application.body.as_ref(),
                    Some(proto::direct_application::Body::Message(_))
                );
                if !is_message || candidate.pairwise_contacts[contact_index].introduction_received {
                    suppress_direct_event = true;
                } else {
                    candidate.pairwise_contacts[contact_index].introduction_received = true;
                }
            }
            (
                Some(proto::pairwise_payload::Body::DirectApplication(application)),
                proto::PairwiseRelationship::OutgoingRequest,
            ) => match application.body.as_ref() {
                Some(proto::direct_application::Body::Acknowledgement(_)) => {}
                Some(proto::direct_application::Body::ContactAcceptance(_)) => {
                    let contact = &mut candidate.pairwise_contacts[contact_index];
                    contact.relationship = proto::PairwiseRelationship::Contact as i32;
                    contact.introduction_sent = false;
                }
                _ => suppress_direct_event = true,
            },
            (Some(proto::pairwise_payload::Body::GroupControl(_)), relationship)
                if relationship != proto::PairwiseRelationship::Contact =>
            {
                return Err(Error::InvalidSignature);
            }
            _ => {}
        }
        Ok((control, sender_contact_card, suppress_direct_event))
    }
}

fn verified_incoming_contact(
    encoded: &[u8],
    sender: [u8; 32],
    initiation_identity: &IdentityBundle,
) -> Result<proto::StoredPairwiseContact, Error> {
    if encoded.is_empty() {
        return Err(Error::InvalidSignature);
    }
    let card = proto::ContactCard::decode(encoded).map_err(|_| Error::Serialization)?;
    if card.version != crate::wire::CONTACT_CARD_VERSION
        || card.relay_urls.len() > crate::wire::MAX_DIRECT_RELAY_URLS
        || card.name.len() > crate::wire::MAX_GROUP_NAME_BYTES
    {
        return Err(Error::InvalidSignature);
    }
    let identity = IdentityBundle::decode(
        &card
            .identity
            .as_ref()
            .ok_or(Error::InvalidSignature)?
            .encode_to_vec(),
    )?;
    identity.verify()?;
    // A public card can carry the chat account's distinct Curve25519 binding.
    // Both bindings are independently signed by the same root; only the core
    // prekey must match the Curve25519 key used by this initiation.
    if identity.identity_key != sender || identity.identity_key != initiation_identity.identity_key
    {
        return Err(Error::InvalidSignature);
    }
    let prekey = PrekeyBundle::decode(&card.pairwise_control_prekey_bundle)?;
    prekey.verify()?;
    if prekey.identity.identity_key != sender
        || prekey.identity.curve_identity_key != initiation_identity.curve_identity_key
    {
        return Err(Error::InvalidSignature);
    }
    for relay in &card.relay_urls {
        if relay.len() > crate::wire::MAX_RELAY_URL_BYTES
            || !(relay.starts_with("wss://")
                || relay.starts_with("ws://")
                || relay.starts_with("https://"))
        {
            return Err(Error::InvalidSignature);
        }
    }
    if card.relay_urls.is_empty() {
        if !card.relay_signature.is_empty() {
            return Err(Error::InvalidSignature);
        }
    } else {
        let relay_transcript = card.relay_urls.join("\n");
        let signature_bytes: [u8; 64] = card
            .relay_signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSignature)?;
        VerifyingKey::from_bytes(&sender)
            .map_err(|_| Error::InvalidKey)?
            .verify_strict(
                relay_transcript.as_bytes(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| Error::InvalidSignature)?;
    }
    Ok(proto::StoredPairwiseContact {
        identity: sender.to_vec(),
        prekey_bundle: card.pairwise_control_prekey_bundle,
        relay_url: card.relay_urls.first().cloned().unwrap_or_default(),
        relationship: proto::PairwiseRelationship::IncomingRequest as i32,
        introduction_received: false,
        introduction_sent: false,
    })
}

fn pairwise_relationship(
    contact: &proto::StoredPairwiseContact,
) -> Result<proto::PairwiseRelationship, Error> {
    match proto::PairwiseRelationship::try_from(contact.relationship)
        .map_err(|_| Error::Serialization)?
    {
        // Checkpoints created before relationship admission shipped only
        // established contacts. Preserve that meaning during upgrade.
        proto::PairwiseRelationship::Unspecified => Ok(proto::PairwiseRelationship::Contact),
        relationship => Ok(relationship),
    }
}
