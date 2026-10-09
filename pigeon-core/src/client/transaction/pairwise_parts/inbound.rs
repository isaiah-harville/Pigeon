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
        let mut crossing_request = false;
        let plaintext = match envelope.body.ok_or(Error::MalformedBundle)? {
            proto::pairwise_envelope::Body::Initiation(bytes) => {
                // A second initiation is admitted only when both sides opened a
                // session before either received the other's (initiation
                // glare): the one existing session is our own and unconfirmed.
                // Once any session with the peer has received a message, later
                // initiations are rejected, so replayed initiations cannot
                // replace or multiply established sessions.
                let existing = candidate
                    .pairwise_sessions
                    .iter()
                    .filter(|session| session.remote_identity.as_slice() == sender)
                    .map(|session| PlatformSession::import(&session.state, sender))
                    .collect::<Result<Vec<_>, _>>()?;
                if existing.len() >= MAX_PAIRWISE_SESSIONS_PER_PEER
                    || existing.iter().any(PlatformSession::has_received_message)
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
                    // A card from a known sender is only valid as a crossing
                    // message request: both sides scanned each other and sent
                    // introductions. The card must still authenticate the
                    // sender; its contents never replace the scanned contact.
                    let known = candidate
                        .pairwise_contacts
                        .iter()
                        .find(|contact| contact.identity.as_slice() == sender)
                        .ok_or(Error::InvalidSignature)?;
                    if pairwise_relationship(known)? != proto::PairwiseRelationship::OutgoingRequest
                    {
                        return Err(Error::InvalidSignature);
                    }
                    verified_incoming_contact(&sender_contact_card, sender, &initiation.identity)?;
                    crossing_request = true;
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
                let message = decode_olm_message(&bytes)?;
                // After initiation glare the peer may send on either session.
                // A failed attempt leaves the stored state untouched; only the
                // session that authenticates the message is advanced.
                let mut last_error = Error::InvalidKey;
                let mut decrypted = None;
                for stored in candidate
                    .pairwise_sessions
                    .iter_mut()
                    .filter(|session| session.remote_identity.as_slice() == sender)
                {
                    let mut session = PlatformSession::import(&stored.state, sender)?;
                    if session.remote_identity_key() != sender {
                        return Err(Error::InvalidSignature);
                    }
                    match session.decrypt(&message) {
                        Ok(plaintext) => {
                            stored.state = session.export()?;
                            decrypted = Some(plaintext);
                            break;
                        }
                        Err(error) => last_error = error,
                    }
                }
                decrypted.ok_or(last_error)?
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
                // Crossing requests are mutual acceptance: each side already
                // chose to message the other, so neither waits on the other's
                // explicit acceptance.
                Some(proto::direct_application::Body::Message(_)) if crossing_request => {
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
