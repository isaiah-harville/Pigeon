impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
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
        let (message, announced) = match envelope.body.ok_or(Error::MalformedBundle)? {
            proto::pairwise_envelope::Body::Initiation(bytes) => {
                let initiation = Initiation::decode(&bytes)?;
                (initiation.message, Some(initiation.identity))
            }
            proto::pairwise_envelope::Body::Message(bytes) => (decode_olm_message(&bytes)?, None),
        };
        // A sender keeps sending pre-key messages until it hears back, and only
        // the first carries an `Initiation` body. Any of them can open the
        // session, so a lost or reordered first message does not strand it.
        let plaintext = match decrypt_on_existing_session(candidate, sender, &message)? {
            Some(plaintext) => {
                // A card only travels with the message that opens a session.
                if !sender_contact_card.is_empty() {
                    return Err(Error::InvalidSignature);
                }
                plaintext
            }
            None => self.stage_establish_inbound_session(
                candidate,
                sender,
                &sender_contact_card,
                announced,
                &message,
            )?,
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
                // A message from the peer is acceptance. Either both sides sent
                // requests (crossing requests) or the peer already added us;
                // each side chose to message the other, so neither waits on
                // an explicit acceptance.
                Some(proto::direct_application::Body::Message(_)) => {
                    let contact = &mut candidate.pairwise_contacts[contact_index];
                    contact.relationship = proto::PairwiseRelationship::Contact as i32;
                    contact.introduction_sent = false;
                    contact.introduction_received = false;
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

    /// Opens a session from a pre-key message that matched no stored session,
    /// admitting an unknown sender through its contact card, and returns the
    /// plaintext.
    fn stage_establish_inbound_session(
        &self,
        candidate: &mut proto::ClientCheckpoint,
        sender: [u8; 32],
        sender_contact_card: &[u8],
        announced: Option<IdentityBundle>,
        message: &OlmMessage,
    ) -> Result<Vec<u8>, Error> {
        // A session we dropped never reopens, so a replayed pre-key message
        // cannot bring back an old ratchet or redeliver its first message.
        if let OlmMessage::PreKey(prekey) = message
            && candidate
                .retired_pairwise_session_ids
                .contains(&prekey.session_id())
        {
            return Err(Error::InvalidSignature);
        }
        // Before any session with the peer has received a message, a second
        // session is admitted only for initiation glare: both sides opened a
        // session before either received the other's, so the one existing
        // session is our own. Once a session is confirmed, a fresh pre-key
        // message means the peer lost its side (it removed and re-added us, or
        // lost its state), so the new session replaces ours. Olm only opens it
        // for a sender holding the peer's identity key.
        let existing = candidate
            .pairwise_sessions
            .iter()
            .filter(|session| session.remote_identity.as_slice() == sender)
            .map(|session| PlatformSession::import(&session.state, sender))
            .collect::<Result<Vec<_>, _>>()?;
        let replaces_confirmed = existing.iter().any(PlatformSession::has_received_message);
        if !replaces_confirmed && existing.len() >= MAX_PAIRWISE_SESSIONS_PER_PEER {
            return Err(Error::InvalidSignature);
        }
        if !candidate
            .pairwise_contacts
            .iter()
            .any(|contact| contact.identity.as_slice() == sender)
        {
            let incoming =
                verified_incoming_contact(sender_contact_card, sender, announced.as_ref())?;
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
            // A known sender's card is a message request that crossed ours,
            // or one sent before the sender learned we had added them. An
            // admitted requester gets no second introduction. The card must
            // still authenticate the sender; its contents never replace the
            // contact we added.
            let known = candidate
                .pairwise_contacts
                .iter()
                .find(|contact| contact.identity.as_slice() == sender)
                .ok_or(Error::InvalidSignature)?;
            if pairwise_relationship(known)? == proto::PairwiseRelationship::IncomingRequest {
                return Err(Error::InvalidSignature);
            }
            verified_incoming_contact(sender_contact_card, sender, announced.as_ref())?;
        }
        let contact = candidate
            .pairwise_contacts
            .iter()
            .find(|contact| contact.identity.as_slice() == sender)
            .ok_or(Error::InvalidSignature)?;
        let registered = PrekeyBundle::decode(&contact.prekey_bundle)?;
        // Without an announced identity, the registered control prekey's
        // signed binding names the Curve25519 key; Olm then refuses a pre-key
        // message sent from any other identity key.
        let registered_curve = registered.identity.curve_identity_key;
        let identity = announced.unwrap_or(registered.identity);
        if identity.identity_key != sender || identity.curve_identity_key != registered_curve
        {
            return Err(Error::InvalidSignature);
        }
        let mut account = pairwise_account(candidate)?.ok_or(Error::InvalidKey)?;
        let (session, plaintext) =
            PlatformSession::establish_inbound(&mut account, &identity, message)?;
        candidate.pairwise_account_state = account.export_state()?;
        candidate.pairwise_fallback_key = account.export_fallback_key().to_vec();
        if replaces_confirmed {
            retire_pairwise_sessions(candidate, sender)?;
        }
        candidate
            .pairwise_sessions
            .push(proto::StoredPairwiseSession {
                remote_identity: sender.to_vec(),
                state: session.export()?,
            });
        Ok(plaintext)
    }
}

pub(super) fn is_addressed_group_control(kind: i32) -> bool {
    matches!(
        proto::OutboundKind::try_from(kind),
        Ok(proto::OutboundKind::GroupJoinRequest
            | proto::OutboundKind::GroupJoinMaterial
            | proto::OutboundKind::GroupWelcome
            | proto::OutboundKind::GroupLeaveProposal)
    )
}

/// Decrypts on the stored session the message belongs to. A pre-key message
/// belongs only to the session whose id it carries, and that session's verdict
/// is final, so a replay fails as a duplicate instead of opening a new session.
/// After initiation glare the peer may send normal messages on either session.
/// Returns `None` for a pre-key message that matches no stored session.
fn decrypt_on_existing_session(
    candidate: &mut proto::ClientCheckpoint,
    sender: [u8; 32],
    message: &OlmMessage,
) -> Result<Option<Vec<u8>>, Error> {
    let prekey_session_id = match message {
        OlmMessage::PreKey(prekey) => Some(prekey.session_id()),
        OlmMessage::Normal(_) => None,
    };
    let mut last_error = Error::InvalidKey;
    for stored in candidate
        .pairwise_sessions
        .iter_mut()
        .filter(|session| session.remote_identity.as_slice() == sender)
    {
        let mut session = PlatformSession::import(&stored.state, sender)?;
        if session.remote_identity_key() != sender {
            return Err(Error::InvalidSignature);
        }
        if let Some(id) = &prekey_session_id {
            if session.session_id() != *id {
                continue;
            }
            let plaintext = session.decrypt(message)?;
            stored.state = session.export()?;
            return Ok(Some(plaintext));
        }
        // A failed attempt leaves the stored state untouched; only the session
        // that authenticates the message is advanced.
        match session.decrypt(message) {
            Ok(plaintext) => {
                stored.state = session.export()?;
                return Ok(Some(plaintext));
            }
            Err(error) => last_error = error,
        }
    }
    match prekey_session_id {
        Some(_) => Ok(None),
        None => Err(last_error),
    }
}

fn verified_incoming_contact(
    encoded: &[u8],
    sender: [u8; 32],
    announced: Option<&IdentityBundle>,
) -> Result<proto::StoredPairwiseContact, Error> {
    if encoded.is_empty() {
        return Err(Error::InvalidSignature);
    }
    let card = proto::ContactCard::decode(encoded).map_err(|_| Error::MalformedBundle)?;
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
    // prekey must match the Curve25519 key the sender announced, if any.
    if identity.identity_key != sender {
        return Err(Error::InvalidSignature);
    }
    let prekey = PrekeyBundle::decode(&card.pairwise_control_prekey_bundle)?;
    prekey.verify()?;
    if prekey.identity.identity_key != sender {
        return Err(Error::InvalidSignature);
    }
    if let Some(announced) = announced
        && (announced.identity_key != sender
            || announced.curve_identity_key != prekey.identity.curve_identity_key)
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

/// Chooses the session to encrypt with: the first one the peer has confirmed by
/// sending on it, otherwise the first (our own unconfirmed outbound session).
fn preferred_session_index(
    candidate: &proto::ClientCheckpoint,
    recipient: [u8; 32],
) -> Result<Option<usize>, Error> {
    let mut first = None;
    for (index, stored) in candidate.pairwise_sessions.iter().enumerate() {
        if stored.remote_identity.as_slice() != recipient {
            continue;
        }
        if PlatformSession::import(&stored.state, recipient)?.has_received_message() {
            return Ok(Some(index));
        }
        first.get_or_insert(index);
    }
    Ok(first)
}

/// Drops every stored session with `peer` and records their ids, so a
/// replayed pre-key message can never reopen one. Once the list is full the
/// oldest ids fall out.
fn retire_pairwise_sessions(
    candidate: &mut proto::ClientCheckpoint,
    peer: [u8; 32],
) -> Result<(), Error> {
    let (retired, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut candidate.pairwise_sessions)
        .into_iter()
        .partition(|session| session.remote_identity.as_slice() == peer);
    candidate.pairwise_sessions = kept;
    for stored in retired {
        let id = PlatformSession::import(&stored.state, peer)?.session_id();
        if candidate.retired_pairwise_session_ids.len() >= crate::MAX_PENDING_OUTBOUND_ENTRIES {
            candidate.retired_pairwise_session_ids.remove(0);
        }
        candidate.retired_pairwise_session_ids.push(id);
    }
    Ok(())
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
