use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use vodozemac::olm::{Account as OlmAccount, AccountPickle, OlmMessage, SessionConfig};

use super::invite::{GroupInviteIntent, GroupInviteTicket};
use super::request::GroupJoinRequest;
use crate::Error;
use crate::identity::{decode_olm_message, encode_olm_message};
use crate::wire::proto;

const REPLY_VERSION: u32 = 1;
const MAX_REPLY_BYTES: usize = 8192;
const MAX_REPLY_STATE_BYTES: usize = 64 * 1024;
const REPLY_DOMAIN: &[u8] = b"pigeon.identity.group-invite-reply.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupInviteReplyStatus {
    Approved,
    Rejected,
    Expired,
    Full,
}

impl GroupInviteReplyStatus {
    fn to_proto(self) -> proto::GroupInviteReplyStatus {
        match self {
            Self::Approved => proto::GroupInviteReplyStatus::Approved,
            Self::Rejected => proto::GroupInviteReplyStatus::Rejected,
            Self::Expired => proto::GroupInviteReplyStatus::Expired,
            Self::Full => proto::GroupInviteReplyStatus::Full,
        }
    }

    fn from_proto(value: i32) -> Result<Self, Error> {
        match proto::GroupInviteReplyStatus::try_from(value) {
            Ok(proto::GroupInviteReplyStatus::Approved) => Ok(Self::Approved),
            Ok(proto::GroupInviteReplyStatus::Rejected) => Ok(Self::Rejected),
            Ok(proto::GroupInviteReplyStatus::Expired) => Ok(Self::Expired),
            Ok(proto::GroupInviteReplyStatus::Full) => Ok(Self::Full),
            _ => Err(Error::MalformedBundle),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GroupInviteReply {
    ticket_digest: [u8; 32],
    request_id: [u8; 32],
    status: GroupInviteReplyStatus,
    join_request: Option<GroupJoinRequest>,
    signature: [u8; 64],
}

impl GroupInviteReply {
    pub(super) fn create(
        signer: &SigningKey,
        ticket: &GroupInviteTicket,
        intent: &GroupInviteIntent,
        status: GroupInviteReplyStatus,
        join_request: Option<&GroupJoinRequest>,
    ) -> Result<Self, Error> {
        intent.verify(ticket)?;
        match (status, join_request) {
            (GroupInviteReplyStatus::Approved, Some(request)) => {
                request.verify()?;
                if request.group_id() != ticket.group_id()
                    || request.coordination_id() != ticket.coordination_id()
                    || request.relay_url() != ticket.relay_url()
                {
                    return Err(Error::InvalidSignature);
                }
            }
            (GroupInviteReplyStatus::Approved, None) | (_, Some(_)) => {
                return Err(Error::MalformedBundle);
            }
            _ => {}
        }
        let ticket_digest = ticket.digest();
        let request_id = intent.request_id();
        let join_request = join_request.cloned();
        let signature = signer
            .sign(&transcript(
                ticket_digest,
                request_id,
                status,
                join_request.as_ref(),
            ))
            .to_bytes();
        Ok(Self {
            ticket_digest,
            request_id,
            status,
            join_request,
            signature,
        })
    }

    fn verify(
        &self,
        ticket: &GroupInviteTicket,
        expected_request_id: [u8; 32],
    ) -> Result<(), Error> {
        if self.ticket_digest != ticket.digest() || self.request_id != expected_request_id {
            return Err(Error::InvalidSignature);
        }
        match (self.status, self.join_request.as_ref()) {
            (GroupInviteReplyStatus::Approved, Some(request)) => {
                request.verify()?;
                if request.group_id() != ticket.group_id()
                    || request.coordination_id() != ticket.coordination_id()
                    || request.relay_url() != ticket.relay_url()
                {
                    return Err(Error::InvalidSignature);
                }
            }
            (GroupInviteReplyStatus::Approved, None) | (_, Some(_)) => {
                return Err(Error::MalformedBundle);
            }
            _ => {}
        }
        let key =
            VerifyingKey::from_bytes(&ticket.inbox_address()).map_err(|_| Error::InvalidKey)?;
        key.verify_strict(
            &transcript(
                self.ticket_digest,
                self.request_id,
                self.status,
                self.join_request.as_ref(),
            ),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::InvalidSignature)
    }

    pub fn status(&self) -> GroupInviteReplyStatus {
        self.status
    }
    pub fn join_request(&self) -> Option<&GroupJoinRequest> {
        self.join_request.as_ref()
    }
    pub fn request_id(&self) -> [u8; 32] {
        self.request_id
    }

    fn encode(&self) -> Vec<u8> {
        proto::GroupInviteReply {
            version: REPLY_VERSION,
            ticket_digest: self.ticket_digest.to_vec(),
            request_id: self.request_id.to_vec(),
            status: self.status.to_proto() as i32,
            group_join_request: self
                .join_request
                .as_ref()
                .map(GroupJoinRequest::encode)
                .unwrap_or_default(),
            signature: self.signature.to_vec(),
        }
        .encode_to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_REPLY_BYTES {
            return Err(Error::ResourceLimit("group invite reply bytes"));
        }
        let wire = proto::GroupInviteReply::decode(bytes).map_err(|_| Error::MalformedBundle)?;
        if wire.encode_to_vec() != bytes {
            return Err(Error::MalformedBundle);
        }
        if wire.version != REPLY_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group invite reply",
                version: wire.version,
            });
        }
        Ok(Self {
            ticket_digest: array(&wire.ticket_digest)?,
            request_id: array(&wire.request_id)?,
            status: GroupInviteReplyStatus::from_proto(wire.status)?,
            join_request: if wire.group_join_request.is_empty() {
                None
            } else {
                Some(GroupJoinRequest::decode(&wire.group_join_request)?)
            },
            signature: wire
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidSignature)?,
        })
    }
}

fn transcript(
    ticket_digest: [u8; 32],
    request_id: [u8; 32],
    status: GroupInviteReplyStatus,
    join_request: Option<&GroupJoinRequest>,
) -> Vec<u8> {
    let request = join_request
        .map(GroupJoinRequest::encode)
        .unwrap_or_default();
    let mut bytes = Vec::with_capacity(REPLY_DOMAIN.len() + 4 + 32 * 2 + 8 + request.len());
    bytes.extend_from_slice(REPLY_DOMAIN);
    bytes.extend_from_slice(&REPLY_VERSION.to_be_bytes());
    bytes.extend_from_slice(&ticket_digest);
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&(status.to_proto() as u32).to_be_bytes());
    bytes.extend_from_slice(&(request.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&request);
    bytes
}

pub struct GroupInviteReplyInbox {
    olm: OlmAccount,
    mailbox_signing_key: SigningKey,
    ticket_digest: [u8; 32],
    request_id: [u8; 32],
    consumed: bool,
    fallback_prekey: [u8; 32],
}

impl GroupInviteReplyInbox {
    pub fn create(ticket: &GroupInviteTicket, request_id: [u8; 32]) -> Result<Self, Error> {
        if request_id == [0; 32] {
            return Err(Error::MalformedBundle);
        }
        let mut olm = OlmAccount::new();
        olm.generate_fallback_key();
        let fallback_prekey = olm
            .fallback_key()
            .into_values()
            .next()
            .ok_or(Error::InvalidKey)?
            .to_bytes();
        let mut seed = [0; 32];
        getrandom::getrandom(&mut seed).map_err(|_| Error::Entropy)?;
        Ok(Self {
            olm,
            mailbox_signing_key: SigningKey::from_bytes(&seed),
            ticket_digest: ticket.digest(),
            request_id,
            consumed: false,
            fallback_prekey,
        })
    }

    pub fn address(&self) -> [u8; 32] {
        self.mailbox_signing_key.verifying_key().to_bytes()
    }
    pub fn curve_identity_key(&self) -> [u8; 32] {
        self.olm.curve25519_key().to_bytes()
    }
    pub fn fallback_prekey(&self) -> [u8; 32] {
        self.fallback_prekey
    }

    pub fn sign_mailbox_challenge(&self, nonce: &[u8]) -> Result<[u8; 64], Error> {
        if nonce.len() != 32 {
            return Err(Error::MalformedBundle);
        }
        Ok(self.mailbox_signing_key.sign(nonce).to_bytes())
    }

    pub fn open_reply(
        &mut self,
        ticket: &GroupInviteTicket,
        ciphertext: &[u8],
        now_ms: i64,
    ) -> Result<GroupInviteReply, Error> {
        ticket.validate(now_ms)?;
        if self.consumed || self.ticket_digest != ticket.digest() {
            return Err(Error::InvalidSignature);
        }
        if ciphertext.len() > MAX_REPLY_BYTES {
            return Err(Error::ResourceLimit("group invite reply ciphertext bytes"));
        }
        let wire =
            proto::GroupInviteCiphertext::decode(ciphertext).map_err(|_| Error::MalformedBundle)?;
        if wire.version != 1 {
            return Err(Error::UnsupportedVersion {
                kind: "group invite ciphertext",
                version: wire.version,
            });
        }
        let sender =
            vodozemac::Curve25519PublicKey::from_bytes(array(&wire.sender_curve_identity_key)?);
        let OlmMessage::PreKey(message) = decode_olm_message(&wire.olm_message)? else {
            return Err(Error::NotAPreKeyMessage);
        };
        let mut candidate = OlmAccount::from_pickle(self.olm.pickle());
        let inbound =
            candidate.create_inbound_session(SessionConfig::default(), sender, &message)?;
        let reply = GroupInviteReply::decode(&inbound.plaintext)?;
        reply.verify(ticket, self.request_id)?;
        self.olm = candidate;
        self.consumed = true;
        Ok(reply)
    }

    pub fn export_state(&self) -> Result<Vec<u8>, Error> {
        let bytes = proto::GroupInviteReplyInboxState {
            version: 1,
            ticket_digest: self.ticket_digest.to_vec(),
            request_id: self.request_id.to_vec(),
            olm_pickle: serde_json::to_vec(&self.olm.pickle()).map_err(|_| Error::Serialization)?,
            mailbox_signing_seed: self.mailbox_signing_key.to_bytes().to_vec(),
            consumed: self.consumed,
            fallback_prekey: self.fallback_prekey.to_vec(),
        }
        .encode_to_vec();
        if bytes.len() > MAX_REPLY_STATE_BYTES {
            return Err(Error::ResourceLimit("group invite reply inbox state bytes"));
        }
        Ok(bytes)
    }

    pub fn import_state(bytes: &[u8], ticket: &GroupInviteTicket) -> Result<Self, Error> {
        if bytes.len() > MAX_REPLY_STATE_BYTES {
            return Err(Error::ResourceLimit("group invite reply inbox state bytes"));
        }
        let state =
            proto::GroupInviteReplyInboxState::decode(bytes).map_err(|_| Error::Serialization)?;
        if state.version != 1 {
            return Err(Error::UnsupportedVersion {
                kind: "group invite reply inbox state",
                version: state.version,
            });
        }
        let ticket_digest = array(&state.ticket_digest)?;
        if ticket_digest != ticket.digest() {
            return Err(Error::InvalidSignature);
        }
        let request_id = array(&state.request_id)?;
        let mailbox_signing_key = SigningKey::from_bytes(&array(&state.mailbox_signing_seed)?);
        let pickle: AccountPickle =
            serde_json::from_slice(&state.olm_pickle).map_err(|_| Error::Serialization)?;
        let olm = OlmAccount::from_pickle(pickle);
        let fallback_prekey = array(&state.fallback_prekey)?;
        Ok(Self {
            olm,
            mailbox_signing_key,
            ticket_digest,
            request_id,
            consumed: state.consumed,
            fallback_prekey,
        })
    }
}

pub(super) fn seal_reply(
    signer: &SigningKey,
    ticket: &GroupInviteTicket,
    intent: &GroupInviteIntent,
    status: GroupInviteReplyStatus,
    join_request: Option<&GroupJoinRequest>,
) -> Result<Vec<u8>, Error> {
    let reply = GroupInviteReply::create(signer, ticket, intent, status, join_request)?;
    let sender = OlmAccount::new();
    let mut session = sender.create_outbound_session(
        SessionConfig::default(),
        vodozemac::Curve25519PublicKey::from_bytes(intent.reply_curve_identity_key()),
        vodozemac::Curve25519PublicKey::from_bytes(intent.reply_prekey()),
    )?;
    let message = session.encrypt(reply.encode())?;
    let bytes = proto::GroupInviteCiphertext {
        version: 1,
        sender_curve_identity_key: sender.curve25519_key().to_bytes().to_vec(),
        olm_message: encode_olm_message(&message),
    }
    .encode_to_vec();
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(Error::ResourceLimit("group invite reply ciphertext bytes"));
    }
    Ok(bytes)
}

fn array(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::MalformedBundle)
}
