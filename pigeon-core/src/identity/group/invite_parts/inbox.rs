/// A short-lived Olm inbox. Its exported state contains private keys and must
/// only be stored inside the presence-gated, transactional client checkpoint.
pub struct GroupInviteInbox {
    olm: OlmAccount,
    mailbox_signing_key: SigningKey,
    ticket_digest: [u8; 32],
    consumed_request_ids: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct GroupInviteMaterial {
    request_id: [u8; 32],
    material: GroupJoinMaterial,
}

impl GroupInviteMaterial {
    pub fn request_id(&self) -> [u8; 32] {
        self.request_id
    }
    pub fn material(&self) -> &GroupJoinMaterial {
        &self.material
    }
}

impl GroupInviteInbox {
    pub fn create(
        group_id: GroupId,
        coordination_id: [u8; 32],
        coordinator_public_key: [u8; 32],
        relay_url: String,
        mode: GroupInviteMode,
        expires_at_ms: i64,
    ) -> Result<(GroupInviteTicket, Self), Error> {
        let mut olm = OlmAccount::new();
        olm.generate_fallback_key();
        let fallback = olm
            .fallback_key()
            .into_values()
            .next()
            .ok_or(Error::InvalidKey)?
            .to_bytes();
        let mut signing_seed = [0; 32];
        getrandom::getrandom(&mut signing_seed).map_err(|_| Error::Entropy)?;
        let mailbox_signing_key = SigningKey::from_bytes(&signing_seed);
        let inbox_address = mailbox_signing_key.verifying_key().to_bytes();
        let ticket = GroupInviteTicket::new(
            group_id,
            coordination_id,
            coordinator_public_key,
            relay_url,
            inbox_address,
            olm.curve25519_key().to_bytes(),
            fallback,
            mode,
            expires_at_ms,
        )?;
        let inbox = Self {
            olm,
            mailbox_signing_key,
            ticket_digest: ticket.digest(),
            consumed_request_ids: Vec::new(),
        };
        Ok((ticket, inbox))
    }

    pub fn seal_request(
        ticket: &GroupInviteTicket,
        intent: &GroupInviteIntent,
        now_ms: i64,
    ) -> Result<Vec<u8>, Error> {
        ticket.validate(now_ms)?;
        intent.verify(ticket)?;
        let sender = OlmAccount::new();
        let recipient = vodozemac::Curve25519PublicKey::from_bytes(ticket.inbox_curve_identity_key);
        let prekey = vodozemac::Curve25519PublicKey::from_bytes(ticket.inbox_fallback_prekey);
        let mut session = sender.create_outbound_session(
            vodozemac::olm::SessionConfig::default(),
            recipient,
            prekey,
        )?;
        let message = session.encrypt(intent.encode())?;
        let ciphertext = proto::GroupInviteCiphertext {
            version: 1,
            sender_curve_identity_key: sender.curve25519_key().to_bytes().to_vec(),
            olm_message: encode_olm_message(&message),
        }
        .encode_to_vec();
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(Error::ResourceLimit("group invite ciphertext bytes"));
        }
        Ok(ciphertext)
    }

    pub fn open_request(
        &mut self,
        ticket: &GroupInviteTicket,
        ciphertext: &[u8],
        now_ms: i64,
    ) -> Result<GroupInviteIntent, Error> {
        ticket.validate(now_ms)?;
        if ticket.digest() != self.ticket_digest {
            return Err(Error::InvalidSignature);
        }
        let (candidate, plaintext) = self.decrypt_content(ciphertext)?;
        let intent = GroupInviteIntent::decode(&plaintext)?;
        intent.verify(ticket)?;
        if self.consumed_request_ids.contains(&intent.request_id()) {
            return Err(Error::InvalidSignature);
        }
        if self.consumed_request_ids.len() >= MAX_CONSUMED_REQUESTS {
            return Err(Error::ResourceLimit("group invite requests"));
        }
        self.olm = candidate;
        self.consumed_request_ids.push(intent.request_id());
        Ok(intent)
    }

    pub fn seal_material(
        ticket: &GroupInviteTicket,
        request_id: [u8; 32],
        material: &GroupJoinMaterial,
        now_ms: i64,
    ) -> Result<Vec<u8>, Error> {
        ticket.validate(now_ms)?;
        if request_id == [0; 32] || material.member_keys().group_id() != ticket.group_id() {
            return Err(Error::InvalidSignature);
        }
        let plaintext = proto::GroupInviteMaterial {
            version: 1,
            ticket_digest: ticket.digest().to_vec(),
            request_id: request_id.to_vec(),
            material: material.encode(),
        }
        .encode_to_vec();
        Self::seal_plaintext(ticket, &plaintext)
    }

    pub fn open_material(
        &mut self,
        ticket: &GroupInviteTicket,
        ciphertext: &[u8],
        now_ms: i64,
    ) -> Result<GroupInviteMaterial, Error> {
        ticket.validate(now_ms)?;
        if ticket.digest() != self.ticket_digest {
            return Err(Error::InvalidSignature);
        }
        let (candidate, plaintext) = self.decrypt_content(ciphertext)?;
        let wire = proto::GroupInviteMaterial::decode(plaintext.as_slice())
            .map_err(|_| Error::MalformedBundle)?;
        if wire.encode_to_vec() != plaintext
            || wire.version != 1
            || array(&wire.ticket_digest)? != self.ticket_digest
        {
            return Err(Error::InvalidSignature);
        }
        let request_id = array(&wire.request_id)?;
        let material = GroupJoinMaterial::decode(&wire.material)?;
        if request_id == [0; 32] || material.member_keys().group_id() != ticket.group_id() {
            return Err(Error::InvalidSignature);
        }
        self.olm = candidate;
        Ok(GroupInviteMaterial {
            request_id,
            material,
        })
    }

    fn decrypt_content(&self, ciphertext: &[u8]) -> Result<(OlmAccount, Vec<u8>), Error> {
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(Error::ResourceLimit("group invite ciphertext bytes"));
        }
        let encoded =
            proto::GroupInviteCiphertext::decode(ciphertext).map_err(|_| Error::MalformedBundle)?;
        if encoded.version != 1 || encoded.encode_to_vec() != ciphertext {
            return Err(Error::MalformedBundle);
        }
        let sender =
            vodozemac::Curve25519PublicKey::from_bytes(array(&encoded.sender_curve_identity_key)?);
        let message = decode_olm_message(&encoded.olm_message)?;
        let OlmMessage::PreKey(prekey_message) = message else {
            return Err(Error::NotAPreKeyMessage);
        };
        let mut candidate = OlmAccount::from_pickle(self.olm.pickle());
        let inbound = candidate.create_inbound_session(
            vodozemac::olm::SessionConfig::default(),
            sender,
            &prekey_message,
        )?;
        Ok((candidate, inbound.plaintext))
    }

    fn seal_plaintext(ticket: &GroupInviteTicket, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let sender = OlmAccount::new();
        let recipient = vodozemac::Curve25519PublicKey::from_bytes(ticket.inbox_curve_identity_key);
        let prekey = vodozemac::Curve25519PublicKey::from_bytes(ticket.inbox_fallback_prekey);
        let mut session = sender.create_outbound_session(
            vodozemac::olm::SessionConfig::default(),
            recipient,
            prekey,
        )?;
        let message = session.encrypt(plaintext)?;
        let ciphertext = proto::GroupInviteCiphertext {
            version: 1,
            sender_curve_identity_key: sender.curve25519_key().to_bytes().to_vec(),
            olm_message: encode_olm_message(&message),
        }
        .encode_to_vec();
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(Error::ResourceLimit("group invite ciphertext bytes"));
        }
        Ok(ciphertext)
    }

    pub fn export_state(&self) -> Result<Vec<u8>, Error> {
        let pickle = serde_json::to_vec(&self.olm.pickle()).map_err(|_| Error::Serialization)?;
        let encoded = proto::GroupInviteInboxState {
            version: 1,
            ticket_digest: self.ticket_digest.to_vec(),
            olm_pickle: pickle,
            consumed_request_ids: self
                .consumed_request_ids
                .iter()
                .map(|id| id.to_vec())
                .collect(),
            mailbox_signing_seed: self.mailbox_signing_key.to_bytes().to_vec(),
        }
        .encode_to_vec();
        if encoded.len() > MAX_INBOX_STATE_BYTES {
            return Err(Error::ResourceLimit("group invite inbox state bytes"));
        }
        Ok(encoded)
    }

    pub fn import_state(state: &[u8], ticket: &GroupInviteTicket) -> Result<Self, Error> {
        if state.len() > MAX_INBOX_STATE_BYTES {
            return Err(Error::ResourceLimit("group invite inbox state bytes"));
        }
        let decoded =
            proto::GroupInviteInboxState::decode(state).map_err(|_| Error::Serialization)?;
        if decoded.version != 1 {
            return Err(Error::UnsupportedVersion {
                kind: "group invite inbox state",
                version: decoded.version,
            });
        }
        let ticket_digest = array(&decoded.ticket_digest)?;
        if ticket_digest != ticket.digest()
            || decoded.consumed_request_ids.len() > MAX_CONSUMED_REQUESTS
        {
            return Err(Error::InvalidSignature);
        }
        let mut consumed_request_ids = Vec::with_capacity(decoded.consumed_request_ids.len());
        for id in decoded.consumed_request_ids {
            let id = array(&id)?;
            if id == [0; 32] || consumed_request_ids.contains(&id) {
                return Err(Error::MalformedBundle);
            }
            consumed_request_ids.push(id);
        }
        let pickle: AccountPickle =
            serde_json::from_slice(&decoded.olm_pickle).map_err(|_| Error::Serialization)?;
        let olm = OlmAccount::from_pickle(pickle);
        if olm.curve25519_key().to_bytes() != ticket.inbox_curve_identity_key {
            return Err(Error::InvalidSignature);
        }
        let mailbox_signing_key = SigningKey::from_bytes(&array(&decoded.mailbox_signing_seed)?);
        if mailbox_signing_key.verifying_key().to_bytes() != ticket.inbox_address {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            olm,
            mailbox_signing_key,
            ticket_digest,
            consumed_request_ids,
        })
    }

    /// Signs the pairwise relay's 32-byte subscription nonce for this invite
    /// mailbox. The private key remains in the sealed inbox state.
    pub fn sign_mailbox_challenge(&self, nonce: &[u8]) -> Result<[u8; 64], Error> {
        if nonce.len() != 32 {
            return Err(Error::MalformedBundle);
        }
        Ok(self.mailbox_signing_key.sign(nonce).to_bytes())
    }

    pub fn seal_reply(
        &self,
        ticket: &GroupInviteTicket,
        intent: &GroupInviteIntent,
        status: GroupInviteReplyStatus,
        join_request: Option<&GroupJoinRequest>,
        now_ms: i64,
    ) -> Result<Vec<u8>, Error> {
        ticket.validate(now_ms)?;
        if ticket.digest() != self.ticket_digest {
            return Err(Error::InvalidSignature);
        }
        seal_reply(
            &self.mailbox_signing_key,
            ticket,
            intent,
            status,
            join_request,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupInviteMode {
    Public,
    Private,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInviteTicket {
    group_id: GroupId,
    coordination_id: [u8; 32],
    coordinator_public_key: [u8; 32],
    relay_url: String,
    inbox_address: [u8; 32],
    inbox_curve_identity_key: [u8; 32],
    inbox_fallback_prekey: [u8; 32],
    bearer_secret: [u8; 32],
    expires_at_ms: i64,
    mode: GroupInviteMode,
}

impl GroupInviteTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group_id: GroupId,
        coordination_id: [u8; 32],
        coordinator_public_key: [u8; 32],
        relay_url: String,
        inbox_address: [u8; 32],
        inbox_curve_identity_key: [u8; 32],
        inbox_fallback_prekey: [u8; 32],
        mode: GroupInviteMode,
        expires_at_ms: i64,
    ) -> Result<Self, Error> {
        let mut bearer_secret = [0; 32];
        getrandom::getrandom(&mut bearer_secret).map_err(|_| Error::Entropy)?;
        let ticket = Self {
            group_id,
            coordination_id,
            coordinator_public_key,
            relay_url,
            inbox_address,
            inbox_curve_identity_key,
            inbox_fallback_prekey,
            bearer_secret,
            expires_at_ms,
            mode,
        };
        ticket.validate_fields()?;
        Ok(ticket)
    }

    pub fn validate(&self, now_ms: i64) -> Result<(), Error> {
        self.validate_fields()?;
        if now_ms >= self.expires_at_ms {
            return Err(Error::MalformedBundle);
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), Error> {
        if self.expires_at_ms <= 0
            || self.coordination_id == [0; 32]
            || self.coordinator_public_key == [0; 32]
            || self.inbox_address == [0; 32]
            || self.inbox_curve_identity_key == [0; 32]
            || self.inbox_fallback_prekey == [0; 32]
            || self.bearer_secret == [0; 32]
            || self.relay_url.len() > MAX_RELAY_URL_BYTES
            || !(self.relay_url.starts_with("wss://") || self.relay_url.starts_with("https://"))
            || self.relay_url.contains(['#', '?', '@'])
        {
            return Err(Error::MalformedBundle);
        }
        Ok(())
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn coordination_id(&self) -> [u8; 32] {
        self.coordination_id
    }

    pub fn coordinator_public_key(&self) -> [u8; 32] {
        self.coordinator_public_key
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    pub fn inbox_address(&self) -> [u8; 32] {
        self.inbox_address
    }

    pub fn inbox_curve_identity_key(&self) -> [u8; 32] {
        self.inbox_curve_identity_key
    }

    pub fn inbox_fallback_prekey(&self) -> [u8; 32] {
        self.inbox_fallback_prekey
    }

    pub fn bearer_secret(&self) -> [u8; 32] {
        self.bearer_secret
    }

    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    pub fn mode(&self) -> GroupInviteMode {
        self.mode
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupInviteTicket {
            version: TICKET_VERSION,
            group_id: self.group_id.as_bytes().to_vec(),
            coordination_id: self.coordination_id.to_vec(),
            coordinator_public_key: self.coordinator_public_key.to_vec(),
            relay_url: self.relay_url.clone(),
            inbox_address: self.inbox_address.to_vec(),
            inbox_curve_identity_key: self.inbox_curve_identity_key.to_vec(),
            inbox_fallback_prekey: self.inbox_fallback_prekey.to_vec(),
            bearer_secret: self.bearer_secret.to_vec(),
            expires_at_ms: self.expires_at_ms,
            mode: match self.mode {
                GroupInviteMode::Public => proto::GroupInviteMode::Public as i32,
                GroupInviteMode::Private => proto::GroupInviteMode::Private as i32,
            },
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_TICKET_BYTES {
            return Err(Error::ResourceLimit("group invite ticket bytes"));
        }
        let wire = proto::GroupInviteTicket::decode(bytes).map_err(|_| Error::Serialization)?;
        if wire.encode_to_vec() != bytes {
            return Err(Error::MalformedBundle);
        }
        if wire.version != TICKET_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group invite ticket",
                version: wire.version,
            });
        }
        let mode = match proto::GroupInviteMode::try_from(wire.mode) {
            Ok(proto::GroupInviteMode::Public) => GroupInviteMode::Public,
            Ok(proto::GroupInviteMode::Private) => GroupInviteMode::Private,
            _ => return Err(Error::MalformedBundle),
        };
        let ticket = Self {
            group_id: GroupId::from_bytes(array(&wire.group_id)?),
            coordination_id: array(&wire.coordination_id)?,
            coordinator_public_key: array(&wire.coordinator_public_key)?,
            relay_url: wire.relay_url,
            inbox_address: array(&wire.inbox_address)?,
            inbox_curve_identity_key: array(&wire.inbox_curve_identity_key)?,
            inbox_fallback_prekey: array(&wire.inbox_fallback_prekey)?,
            bearer_secret: array(&wire.bearer_secret)?,
            expires_at_ms: wire.expires_at_ms,
            mode,
        };
        ticket.validate_fields()?;
        Ok(ticket)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInviteIntent {
    ticket_digest: [u8; 32],
    requester_identity: [u8; 32],
    request_id: [u8; 32],
    reply_address: [u8; 32],
    reply_curve_identity_key: [u8; 32],
    reply_prekey: [u8; 32],
    signature: [u8; 64],
}
