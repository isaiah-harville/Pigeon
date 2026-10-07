impl GroupInviteIntent {
    pub fn create(
        identity: &impl SecureIdentity,
        ticket: &GroupInviteTicket,
        request_id: [u8; 32],
        reply_address: [u8; 32],
        reply_curve_identity_key: [u8; 32],
        reply_prekey: [u8; 32],
    ) -> Result<Self, Error> {
        let requester_identity = identity.ensure_public_key(IdentityPurpose::Root)?;
        let ticket_digest = ticket.digest();
        let signature = identity.sign(
            IdentityPurpose::Root,
            &intent_transcript(
                ticket_digest,
                requester_identity,
                request_id,
                reply_address,
                reply_curve_identity_key,
                reply_prekey,
            ),
        )?;
        let intent = Self {
            ticket_digest,
            requester_identity,
            request_id,
            reply_address,
            reply_curve_identity_key,
            reply_prekey,
            signature,
        };
        intent.verify(ticket)?;
        Ok(intent)
    }

    pub fn verify(&self, ticket: &GroupInviteTicket) -> Result<(), Error> {
        if self.ticket_digest != ticket.digest()
            || self.request_id == [0; 32]
            || self.reply_address == [0; 32]
            || self.reply_curve_identity_key == [0; 32]
            || self.reply_prekey == [0; 32]
        {
            return Err(Error::InvalidSignature);
        }
        let key =
            VerifyingKey::from_bytes(&self.requester_identity).map_err(|_| Error::InvalidKey)?;
        key.verify_strict(
            &intent_transcript(
                self.ticket_digest,
                self.requester_identity,
                self.request_id,
                self.reply_address,
                self.reply_curve_identity_key,
                self.reply_prekey,
            ),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::InvalidSignature)
    }

    pub fn requester_identity(&self) -> [u8; 32] {
        self.requester_identity
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.request_id
    }

    pub fn reply_prekey(&self) -> [u8; 32] {
        self.reply_prekey
    }

    pub fn reply_address(&self) -> [u8; 32] {
        self.reply_address
    }

    pub fn reply_curve_identity_key(&self) -> [u8; 32] {
        self.reply_curve_identity_key
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupInviteIntent {
            version: INTENT_VERSION,
            ticket_digest: self.ticket_digest.to_vec(),
            requester_identity: self.requester_identity.to_vec(),
            request_id: self.request_id.to_vec(),
            reply_prekey: self.reply_prekey.to_vec(),
            signature: self.signature.to_vec(),
            reply_address: self.reply_address.to_vec(),
            reply_curve_identity_key: self.reply_curve_identity_key.to_vec(),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(Error::ResourceLimit("group invite intent bytes"));
        }
        let wire = proto::GroupInviteIntent::decode(bytes).map_err(|_| Error::Serialization)?;
        if wire.encode_to_vec() != bytes {
            return Err(Error::MalformedBundle);
        }
        if wire.version != INTENT_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group invite intent",
                version: wire.version,
            });
        }
        Ok(Self {
            ticket_digest: array(&wire.ticket_digest)?,
            requester_identity: array(&wire.requester_identity)?,
            request_id: array(&wire.request_id)?,
            reply_address: array(&wire.reply_address)?,
            reply_curve_identity_key: array(&wire.reply_curve_identity_key)?,
            reply_prekey: array(&wire.reply_prekey)?,
            signature: wire
                .signature
                .try_into()
                .map_err(|_| Error::InvalidSignature)?,
        })
    }
}

fn intent_transcript(
    ticket_digest: [u8; 32],
    requester_identity: [u8; 32],
    request_id: [u8; 32],
    reply_address: [u8; 32],
    reply_curve_identity_key: [u8; 32],
    reply_prekey: [u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(INTENT_DOMAIN.len() + 4 + 32 * 6);
    transcript.extend_from_slice(INTENT_DOMAIN);
    transcript.extend_from_slice(&INTENT_VERSION.to_be_bytes());
    transcript.extend_from_slice(&ticket_digest);
    transcript.extend_from_slice(&requester_identity);
    transcript.extend_from_slice(&request_id);
    transcript.extend_from_slice(&reply_address);
    transcript.extend_from_slice(&reply_curve_identity_key);
    transcript.extend_from_slice(&reply_prekey);
    transcript
}

fn array(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::MalformedBundle)
}
