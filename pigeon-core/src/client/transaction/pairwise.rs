use prost::Message;

use super::{PigeonClient, pairwise_account};
use crate::client::{ClientOutput, OutboundItem};
use crate::identity::{
    Initiation, PlatformSession, PrekeyBundle, decode_olm_message, encode_olm_message,
};
use crate::storage::StateStore;
use crate::wire::{PROTOCOL_VERSION, proto};
use crate::{Error, SecureIdentity};

impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
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
        };
        if let Some(existing) = candidate
            .pairwise_contacts
            .iter_mut()
            .find(|existing| existing.identity.as_slice() == bundle.identity.identity_key)
        {
            *existing = stored;
        } else {
            candidate.pairwise_contacts.push(stored);
        }
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
        let contact = candidate
            .pairwise_contacts
            .iter()
            .find(|contact| contact.identity.as_slice() == recipient)
            .ok_or(Error::InvalidKey)?
            .clone();
        let local_identity = self
            .identity
            .ensure_public_key(crate::IdentityPurpose::Root)?;
        let plaintext = proto::PairwiseControlPayload {
            version: PROTOCOL_VERSION,
            sender_identity: local_identity.to_vec(),
            recipient_identity: recipient.to_vec(),
            content_kind: content_kind
                .try_into()
                .map_err(|_| Error::MalformedBundle)?,
            payload,
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
                body: Some(body),
            }
            .encode_to_vec(),
        })
    }

    pub(super) fn stage_apply_pairwise_control(
        &self,
        inbound: &proto::ApplyInbound,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<proto::PairwiseControlPayload, Error> {
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
        if recipient != local_identity
            || !candidate
                .pairwise_contacts
                .iter()
                .any(|contact| contact.identity.as_slice() == sender)
        {
            return Err(Error::InvalidSignature);
        }

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
                if initiation.identity.identity_key != sender {
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
        let control = proto::PairwiseControlPayload::decode(plaintext.as_slice())
            .map_err(|_| Error::MalformedBundle)?;
        if control.version != PROTOCOL_VERSION
            || control.sender_identity.as_slice() != sender
            || control.recipient_identity.as_slice() != recipient
            || !matches!(
                proto::OutboundKind::try_from(
                    i32::try_from(control.content_kind).map_err(|_| Error::MalformedBundle)?
                )
                .map_err(|_| Error::MalformedBundle)?,
                proto::OutboundKind::GroupJoinRequest
                    | proto::OutboundKind::GroupJoinMaterial
                    | proto::OutboundKind::GroupWelcome
            )
        {
            return Err(Error::InvalidSignature);
        }
        Ok(control)
    }
}
